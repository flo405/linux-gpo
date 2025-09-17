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
	"os"
	"strings"
)

// ComputeDeviceHashFromPrivateKey ALWAYS derives the public key from the PRIVATE key,
// then returns the SHA-256 of the RAW Ed25519 public key bytes (32 bytes).
// Supports both OpenSSH private keys and PKCS#8 private keys.
func ComputeDeviceHashFromPrivateKey(privPath string) (string, []byte, error) {
	keyPEM, err := os.ReadFile(privPath)
	if err != nil {
		return "", nil, fmt.Errorf("read private key: %w", err)
	}

	// OpenSSH private key (-----BEGIN OPENSSH PRIVATE KEY-----)
	if strings.Contains(string(keyPEM), "BEGIN OPENSSH PRIVATE KEY") {
		privAny, err := ssh.ParseRawPrivateKey(keyPEM)
		if err != nil {
			return "", nil, fmt.Errorf("parse OpenSSH private key: %w", err)
		}
		switch k := privAny.(type) {
		case ed25519.PrivateKey:
			return hashFromPriv(k)
		case *ed25519.PrivateKey:
			return hashFromPriv(*k)
		default:
			return "", nil, errors.New("unsupported OpenSSH private key type (need Ed25519)")
		}
	}

	// Legacy PKCS#8 (-----BEGIN PRIVATE KEY-----). We keep this for compatibility,
	// but the installer now generates OpenSSH keys only.
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
	return hashFromPriv(priv)
}

// hashFromPriv computes SHA-256 over RAW Ed25519 public key bytes,
// and also returns a PEM-encoded SPKI for logging or diagnostics (not used in the hash).
func hashFromPriv(priv ed25519.PrivateKey) (string, []byte, error) {
	pub := priv.Public().(ed25519.PublicKey) // 32 bytes
	sum := sha256.Sum256(pub)
	hexHash := strings.ToLower(hex.EncodeToString(sum[:]))

	// Produce PEM (SPKI) as a convenience for logs/inspection (not used for hashing)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", nil, fmt.Errorf("marshal public key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return hexHash, pemBytes, nil
}
