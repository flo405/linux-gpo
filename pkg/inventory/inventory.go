package inventory

import (
	"golang.org/x/crypto/ssh"

	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// inventory/devices.yml schema
type DeviceInventory struct {
	APIVersion string        `yaml:"apiVersion"`
	Kind       string        `yaml:"kind"`
	Items      []DeviceEntry `yaml:"items"`
}

type DeviceEntry struct {
	DevicePubSHA256 string            `yaml:"device_pub_sha256"`
	Identity        string            `yaml:"identity"`
	Tags            map[string]string `yaml:"tags"`
}

// ComputeDeviceHashFromPrivateKey loads a PKCS#8 Ed25519 private key PEM and returns
// (hex SHA-256 of public key PEM, public key PEM bytes).
func ComputeDeviceHashFromPrivateKey(path string) (string, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("read private key: %w", err)
	}

	// Try OpenSSH private key first (-----BEGIN OPENSSH PRIVATE KEY-----)
	if strings.Contains(string(b), "BEGIN OPENSSH PRIVATE KEY") {
		privAny, err := ssh.ParseRawPrivateKey(b)
		if err != nil {
			return "", nil, fmt.Errorf("parse OpenSSH private key: %w", err)
		}
		// Expect Ed25519
		switch k := privAny.(type) {
		case ed25519.PrivateKey:
			pub := k.Public().(ed25519.PublicKey)
			der, err := x509.MarshalPKIXPublicKey(pub)
			if err != nil { return "", nil, fmt.Errorf("marshal public key: %w", err) }
			pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
			sum := sha256.Sum256(pubPEM)
			return strings.ToLower(hex.EncodeToString(sum[:])), pubPEM, nil
		case *ed25519.PrivateKey:
			pub := (*k).Public().(ed25519.PublicKey)
			der, err := x509.MarshalPKIXPublicKey(pub)
			if err != nil { return "", nil, fmt.Errorf("marshal public key: %w", err) }
			pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
			sum := sha256.Sum256(pubPEM)
			return strings.ToLower(hex.EncodeToString(sum[:])), pubPEM, nil
		default:
			return "", nil, errors.New("unsupported private key type (expected Ed25519)")
		}
	}

	// Fallback: legacy PKCS#8 (-----BEGIN PRIVATE KEY-----)
	block, _ := pem.Decode(b)
	if block == nil || !strings.Contains(block.Type, "PRIVATE KEY") {
		return "", nil, errors.New("invalid PEM: no PRIVATE KEY block found")
	}
	privAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	priv, ok := privAny.(ed25519.PrivateKey)
	if !ok || len(priv) == 0 {
		return "", nil, errors.New("could not derive Ed25519 private key")
	}
	pub := priv.Public().(ed25519.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", nil, fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	sum := sha256.Sum256(pubPEM)
	return strings.ToLower(hex.EncodeToString(sum[:])), pubPEM, nil
}


// loadInventory reads inventory/devices.yml from cacheDir.
func loadInventory(cacheDir string) (*DeviceInventory, error) {
	path := filepath.Join(cacheDir, "inventory", "devices.yml")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var inv DeviceInventory
	if err := yaml.Unmarshal(b, &inv); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &inv, nil
}

// writeManagedTag writes a single tag into tagsDir as <key>.tag.
// If an existing file does NOT look managed by us, it will write to inventory.<key>.tag instead,
// to avoid clobbering admin-created tags.
// OVERWRITE VERSION: always write <key>.tag atomically.
// If a file existed and wasn't ours, keep a one-time backup at <key>.tag.bak.
func writeManagedTag(tagsDir, key, value string) (string, error) {
	target := filepath.Join(tagsDir, key+".tag")
	content := "# managed-by: lgpod-inventory\n" + strings.TrimSpace(value) + "\n"

	if err := os.MkdirAll(tagsDir, 0o750); err != nil {
		return "", fmt.Errorf("create tags dir: %w", err)
	}

	// Backup if file exists and wasn't ours
	if b, err := os.ReadFile(target); err == nil {
		if !strings.HasPrefix(string(b), "# managed-by: lgpod-inventory") {
			_ = os.WriteFile(target+".bak", b, 0o640) // best-effort
		}
	}

	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o640); err != nil {
		return "", fmt.Errorf("write temp tag file: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		return "", fmt.Errorf("rename tag file: %w", err)
	}
	return target, nil
}

// Remove all previously managed tags except the keys in 'keep' (map of tag keys to keep).
func cleanManagedTagsExcept(tagsDir string, keep map[string]struct{}) (int, error) {
	ents, err := os.ReadDir(tagsDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	for _, de := range ents {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".tag") {
			continue
		}
		key := strings.TrimSuffix(de.Name(), ".tag")
		if _, ok := keep[key]; ok {
			continue
		}
		path := filepath.Join(tagsDir, de.Name())
		b, _ := os.ReadFile(path)
		if strings.HasPrefix(string(b), "# managed-by: lgpod-inventory") {
			_ = os.Remove(path)
			removed++
		}
	}
	return removed, nil
}


// SyncInventoryTags computes the device hash, looks it up in inventory/devices.yml,
// and writes tags to tagsDir. Returns (deviceHash, numberOfFilesWritten).
func SyncInventoryTags(cacheDir, tagsDir, deviceKeyPath string) (string, int, error) {
	hash, _, err := ComputeDeviceHashPreferPub(deviceKeyPath)
	if err != nil {
		return "", 0, err
	}

	inv, err := loadInventory(cacheDir)
	if err != nil {
		return hash, 0, err
	}

	var match *DeviceEntry
	for i := range inv.Items {
		if strings.EqualFold(inv.Items[i].DevicePubSHA256, hash) {
			match = &inv.Items[i]
			break
		}
	}
	if match == nil {
		// No mapping for this device — remove our previously managed tags (if any)
		_, _ = cleanManagedTagsExcept(tagsDir, map[string]struct{}{}) // keep none
		return hash, 0, nil
	}

	// Build 'keep' set (identity tag is optional but useful)
	keep := make(map[string]struct{}, len(match.Tags)+1)
	for k := range match.Tags {
		if strings.TrimSpace(k) != "" {
			keep[k] = struct{}{}
		}
	}
	if match.Identity != "" {
		keep["identity"] = struct{}{}
	}

	// Remove stale managed tags not in inventory
	_, _ = cleanManagedTagsExcept(tagsDir, keep)

	// Write current tags
	wrote := 0
	for k, v := range match.Tags {
		if strings.TrimSpace(k) == "" {
			continue
		}
		if _, err := writeManagedTag(tagsDir, k, v); err != nil {
			return hash, wrote, fmt.Errorf("write tag %q: %w", k, err)
		}
		wrote++
	}
	if match.Identity != "" {
		if _, err := writeManagedTag(tagsDir, "identity", match.Identity); err == nil {
			wrote++
		}
	}
	return hash, wrote, nil
}

// CleanManagedTags can be used if you ever want to delete only the tags created by us.
func CleanManagedTags(tagsDir string) (int, error) {
	dirEntries, err := os.ReadDir(tagsDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		if !strings.HasSuffix(de.Name(), ".tag") {
			continue
		}
		path := filepath.Join(tagsDir, de.Name())
		b, _ := os.ReadFile(path)
		if strings.HasPrefix(string(b), "# managed-by: lgpod-inventory") {
			_ = os.Remove(path)
			removed++
		}
	}
	return removed, nil
}


// ComputeDeviceHashFromOpenSSHPub reads an OpenSSH public key file (ssh-ed25519 ...)
// converts it into PKIX/PEM and returns (hex sha256 of PEM, PEM bytes).
func ComputeDeviceHashFromOpenSSHPub(pubPath string) (string, []byte, error) {
	b, err := os.ReadFile(pubPath)
	if err != nil {
		return "", nil, fmt.Errorf("read public key: %w", err)
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return "", nil, fmt.Errorf("parse OpenSSH public key: %w", err)
	}
	cp, ok := pk.(ssh.CryptoPublicKey)
	if !ok {
		return "", nil, errors.New("public key does not expose crypto key")
	}
	goPub := cp.CryptoPublicKey()
	der, err := x509.MarshalPKIXPublicKey(goPub)
	if err != nil {
		return "", nil, fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	sum := sha256.Sum256(pubPEM)
	return strings.ToLower(hex.EncodeToString(sum[:])), pubPEM, nil
}

// ComputeDeviceHashPreferPub prefers /etc/lgpo/device.pub (OpenSSH) when present,
// and falls back to the legacy PKCS#8 private key format.
func ComputeDeviceHashPreferPub(deviceKeyPath string) (string, []byte, error) {
	pubPath := strings.TrimSuffix(deviceKeyPath, ".key") + ".pub"
	if _, err := os.Stat(pubPath); err == nil {
		return ComputeDeviceHashFromOpenSSHPub(pubPath)
	}
	return ComputeDeviceHashFromPrivateKey(deviceKeyPath)
}
