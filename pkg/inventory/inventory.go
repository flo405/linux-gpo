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

// ----- inventory/devices.yml schema -----

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

// ----- Hashing helpers -----

// hashOpenSSHBlob computes SHA-256 over the OpenSSH wire format of the public key
// (the same bytes you get by base64-decoding the "ssh-ed25519 AAAA..." middle field).
func hashOpenSSHBlob(pub ed25519.PublicKey) (string, []byte, error) {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", nil, fmt.Errorf("ssh.NewPublicKey: %w", err)
	}
	blob := sshPub.Marshal() // canonical OpenSSH wire format
	sum := sha256.Sum256(blob)

	// PEM only for diagnostics/logs (NOT used for hashing)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", nil, fmt.Errorf("marshal public key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	return strings.ToLower(hex.EncodeToString(sum[:])), pemBytes, nil
}

// ComputeDeviceHashFromPrivateKey derives the Ed25519 public key from the PRIVATE key
// (OpenSSH or PKCS#8) and returns:
//  - hex SHA-256 of the OpenSSH public key blob (canonical), and
//  - a PEM-encoded SPKI for diagnostics (not used in hashing).
func ComputeDeviceHashFromPrivateKey(privPath string) (string, []byte, error) {
	keyPEM, err := os.ReadFile(privPath)
	if err != nil {
		return "", nil, fmt.Errorf("read private key: %w", err)
	}

	// OpenSSH private key?
	if strings.Contains(string(keyPEM), "BEGIN OPENSSH PRIVATE KEY") {
		privAny, err := ssh.ParseRawPrivateKey(keyPEM)
		if err != nil {
			return "", nil, fmt.Errorf("parse OpenSSH private key: %w", err)
		}
		switch k := privAny.(type) {
		case ed25519.PrivateKey:
			return hashOpenSSHBlob(k.Public().(ed25519.PublicKey))
		case *ed25519.PrivateKey:
			return hashOpenSSHBlob(k.Public().(ed25519.PublicKey))
		default:
			return "", nil, errors.New("unsupported OpenSSH private key type (need Ed25519)")
		}
	}

	// Legacy PKCS#8 (kept for compatibility).
	block, _ := pem.Decode(keyPEM)
	if block == nil || !strings.Contains(block.Type, "PRIVATE KEY") {
		return "", nil, errors.New("invalid PEM: no PRIVATE KEY block found")
	}
	privAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	priv, ok := privAny.(ed25519.PrivateKey)
	if !ok || len(priv) == 0 {
		return "", nil, errors.New("not an Ed25519 private key")
	}
	return hashOpenSSHBlob(priv.Public().(ed25519.PublicKey))
}

// ComputeDeviceHashFromOpenSSHPub reads an OpenSSH-format public key file and
// returns (hex SHA-256 of the OpenSSH blob, PEM SPKI for diagnostics).
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
	ed, ok := goPub.(ed25519.PublicKey)
	if !ok {
		return "", nil, errors.New("not an Ed25519 public key")
	}
	return hashOpenSSHBlob(ed)
}

// For run.go compatibility. We standardize on the private key we own.
func ComputeDeviceHashPreferPub(deviceKeyPath string) (string, []byte, error) {
	return ComputeDeviceHashFromPrivateKey(deviceKeyPath)
}

// ----- Inventory/tagging -----

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

// Writes a single tag (managed marker, atomic replace).
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

// Remove previously managed tags except keys in 'keep'.
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

// SyncInventoryTags computes the device hash (from PRIVATE key), looks it up in inventory/devices.yml,
// writes tags; returns (deviceHash, filesWritten).
func SyncInventoryTags(cacheDir, tagsDir, deviceKeyPath string) (string, int, error) {
	hash, _, err := ComputeDeviceHashFromPrivateKey(deviceKeyPath)
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
		_, _ = cleanManagedTagsExcept(tagsDir, map[string]struct{}{}) // keep none
		return hash, 0, nil
	}

	keep := make(map[string]struct{}, len(match.Tags)+1)
	for k := range match.Tags {
		if strings.TrimSpace(k) != "" {
			keep[k] = struct{}{}
		}
	}
	if match.Identity != "" {
		keep["identity"] = struct{}{}
	}
	_, _ = cleanManagedTagsExcept(tagsDir, keep)

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
