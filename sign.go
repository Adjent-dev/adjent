package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
)

// Entries are signed because a hash chain alone falls to an attacker with write
// access: they can rebuild it from any point and produce a valid chain saying
// anything. Signing raises the bar to key compromise. External anchoring, which
// would close it entirely, is not implemented.

const (
	privatePEMType = "PRIVATE KEY"
	publicPEMType  = "PUBLIC KEY"
)

// keyID fingerprints a public key so a verifier knows which key to check.
func keyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

func generateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating key: %w", err)
	}
	return pub, priv, nil
}

// savePrivateKey writes PKCS#8 PEM. Mode is set at creation, not after, so the
// key is never briefly world-readable.
func savePrivateKey(path string, priv ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("encoding private key: %w", err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists; refusing to overwrite a signing key", path)
		}
		return fmt.Errorf("creating private key file: %w", err)
	}
	defer f.Close()

	return pem.Encode(f, &pem.Block{Type: privatePEMType, Bytes: der})
}

func savePublicKey(path string, pub ed25519.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("encoding public key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("creating public key file: %w", err)
	}
	defer f.Close()

	return pem.Encode(f, &pem.Block{Type: publicPEMType, Bytes: der})
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}

	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("private key %s is readable by other users (mode %04o); run: chmod 600 %s",
			path, info.Mode().Perm(), path)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("private key %s is not PEM encoded", path)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key %s is %T, but adjent signs with Ed25519", path, parsed)
	}
	return priv, nil
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading public key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("public key %s is not PEM encoded", path)
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key %s is %T, but adjent signs with Ed25519", path, parsed)
	}
	return pub, nil
}

// signEntryHash signs the entry hash, which already commits to every field and
// to the predecessor, so the signature covers the entry and its position.
func signEntryHash(priv ed25519.PrivateKey, entryHash string) string {
	return hex.EncodeToString(ed25519.Sign(priv, []byte(entryHash)))
}

func verifyEntrySignature(pub ed25519.PublicKey, entryHash, signature string) bool {
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, []byte(entryHash), sig)
}
