package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)


func safeKeyName(s string) string {
	// keep only [A-Za-z0-9._-] to make safe filenames
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	return b.String()
}


type rsaStore struct {
	mu       sync.Mutex
	priv     *rsa.PrivateKey
	pubPEM   string
	privPEM  string
	keyPath  string
	privPath string
	prefix string
	legacyKeyPath  string
	legacyPrivPath string
	legacyOwnerPath string
}

func newRSAStore() *rsaStore {
	dir := os.Getenv("AGENT_DATA_DIR")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".securedata_agent")
	}
	_ = os.MkdirAll(dir, 0o700)

	user := safeKeyName(os.Getenv("AGENT_USER"))
	org := safeKeyName(os.Getenv("AGENT_ORG"))
	prefix := user
	if org != "" && user != "" {
		prefix = org + "_" + user
	}
	if prefix == "" {
		prefix = "default"
	}

	return &rsaStore{
		prefix:          prefix,
		keyPath:         filepath.Join(dir, fmt.Sprintf("rsa_public_%s.pem", prefix)),
		privPath:        filepath.Join(dir, fmt.Sprintf("rsa_private_%s.pem", prefix)),
		legacyKeyPath:   filepath.Join(dir, "rsa_public.pem"),
		legacyPrivPath:  filepath.Join(dir, "rsa_private.pem"),
		legacyOwnerPath: filepath.Join(dir, "rsa_legacy_owner.txt"),
	}
}

func (s *rsaStore) ensureLoaded() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.priv != nil && s.pubPEM != "" && s.privPEM != "" {
		return nil
	}

	// try load from disk
	pubB, pubErr := os.ReadFile(s.keyPath)
	privB, privErr := os.ReadFile(s.privPath)

	// Backward-compatible migration: legacy keys were stored under fixed filenames.
	// We migrate them to the per-user filenames ONLY for the first prefix that claims them
	// (recorded in rsa_legacy_owner.txt). This prevents every user on the same machine
	// from accidentally sharing the same RSA keypair.
	if (pubErr != nil || privErr != nil) && s.legacyKeyPath != "" && s.legacyPrivPath != "" {
		claimedBy := ""
		if b, err := os.ReadFile(s.legacyOwnerPath); err == nil {
			claimedBy = strings.TrimSpace(string(b))
		}
		if claimedBy == "" {
			// first run after upgrade: claim legacy keys for this prefix
			_ = os.WriteFile(s.legacyOwnerPath, []byte(s.prefix), 0o600)
			claimedBy = s.prefix
		}
		if claimedBy == s.prefix {
			lPubB, lPubErr := os.ReadFile(s.legacyKeyPath)
			lPrivB, lPrivErr := os.ReadFile(s.legacyPrivPath)
			if lPubErr == nil && lPrivErr == nil {
				_ = os.WriteFile(s.keyPath, lPubB, 0o600)
				_ = os.WriteFile(s.privPath, lPrivB, 0o600)
				pubB, pubErr = lPubB, nil
				privB, privErr = lPrivB, nil
			}
		}
	}
	if pubErr == nil && privErr == nil {
		privKey, err := parseRSAPrivateKeyPEM(string(privB))
		if err != nil {
			return err
		}
		s.priv = privKey
		s.pubPEM = string(pubB)
		s.privPEM = string(privB)
		return nil
	}

	// generate new
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	privPEM, pubPEM, err := marshalRSAKeyPairPEM(key)
	if err != nil {
		return err
	}

	if err := os.WriteFile(s.keyPath, []byte(pubPEM), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(s.privPath, []byte(privPEM), 0o600); err != nil {
		return err
	}

	s.priv = key
	s.pubPEM = pubPEM
	s.privPEM = privPEM
	return nil
}

func (s *rsaStore) publicPEM() (string, error) {
	if err := s.ensureLoaded(); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pubPEM, nil
}

func (s *rsaStore) decryptBase64PKCS1v15(ciphertextB64 string) (string, error) {
	if err := s.ensureLoaded(); err != nil {
		return "", err
	}
	s.mu.Lock()
	priv := s.priv
	s.mu.Unlock()

	raw, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("invalid base64 ciphertext: %w", err)
	}
	plain, err := rsa.DecryptPKCS1v15(rand.Reader, priv, raw)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func marshalRSAKeyPairPEM(priv *rsa.PrivateKey) (privPEM string, pubPEM string, err error) {
	privDER := x509.MarshalPKCS1PrivateKey(priv)
	privBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER}
	privPEM = string(pem.EncodeToMemory(privBlock))

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", "", err
	}
	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}
	pubPEM = string(pem.EncodeToMemory(pubBlock))

	return privPEM, pubPEM, nil
}

func parseRSAPrivateKeyPEM(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	if block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected PEM type: %s", block.Type)
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

type rsaDecryptRequest struct {
	Ciphertext string `json:"ciphertext"`
}

type rsaDecryptResponse struct {
	Plaintext string `json:"plaintext"`
}

func handleRSAPublicKey(store *rsaStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pub, err := store.publicPEM()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(pub))
	}
}

func handleRSADecrypt(store *rsaStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req rsaDecryptRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if req.Ciphertext == "" {
			http.Error(w, "ciphertext is required", http.StatusBadRequest)
			return
		}
		plain, err := store.decryptBase64PKCS1v15(req.Ciphertext)
		if err != nil {
			http.Error(w, "decrypt failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rsaDecryptResponse{Plaintext: plain})
	}
}
