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

// hashSPKIDER returns (hex sha256 of DER SPKI, PEM-encoded public key bytes)
func hashSPKIDER(pub ed25519.PublicKey) (string, []byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", nil, fmt.Errorf("marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	// PEM only for logging/compat; the hash is over DER (canonical, no wrap/newline issues).
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return strings.ToLower(hex.EncodeToString(sum[:])), pemBytes, nil
}

// ComputeDeviceHashFromPrivateKey ALWAYS derives the public key from the PRIVATE key,
// then returns the SHA-256 of the SPKI DER of that public key.
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
			pub := k.Public().(ed25519.PublicKey)
			return hashSPKIDER(pub)
		case *ed25519.PrivateKey:
			pub := (*k).Public().(ed25519.PublicKey)
			return hashSPKIDER(pub)
		default:
			return "", nil, errors.New("unsupported OpenSSH private key type (need Ed25519)")
		}
	}

	// Legacy PKCS#8 (-----BEGIN PRIVATE KEY-----)
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
	pub := priv.Public().(ed25519.PublicKey)
	return hashSPKIDER(pub)
}
