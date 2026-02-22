//go:build legacy
// +build legacy

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
)

func rsaKeyDir(cfg AgentConfig) string {
	home, _ := os.UserHomeDir()
	// ключи привязываем к пользователю агента (Ruslan/MLService/...)
	return filepath.Join(home, ".securedata-agent", cfg.Org, cfg.User)
}

func loadOrCreateRSA(cfg AgentConfig) (*rsa.PrivateKey, string, string, error) {
	dir := rsaKeyDir(cfg)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", "", err
	}

	privPath := filepath.Join(dir, "rsa_private.pem")

	// 1) load existing
	if b, err := os.ReadFile(privPath); err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, "", "", errors.New("failed to decode rsa_private.pem")
		}
		var privAny any
		privAny, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			// fallback PKCS1
			pkcs1, err2 := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err2 != nil {
				return nil, "", "", err
			}
			priv := pkcs1
			pubPem, fp, err := exportPublic(priv)
			return priv, pubPem, fp, err
		}
		priv, ok := privAny.(*rsa.PrivateKey)
		if !ok {
			return nil, "", "", errors.New("rsa_private.pem is not RSA key")
		}
		pubPem, fp, err := exportPublic(priv)
		return priv, pubPem, fp, err
	}

	// 2) create new
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", "", err
	}
	privDer, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, "", "", err
	}
	privPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDer})
	if err := os.WriteFile(privPath, privPem, 0o600); err != nil {
		return nil, "", "", err
	}

	pubPem, fp, err := exportPublic(priv)
	return priv, pubPem, fp, err
}

func exportPublic(priv *rsa.PrivateKey) (pubPem string, fingerprint string, err error) {
	pubDer, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", "", err
	}
	pubPemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})

	sum := sha256.Sum256(pubDer)
	fingerprint = hex.EncodeToString(sum[:])

	return string(pubPemBytes), fingerprint, nil
}

func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func handlerRSAInfo(priv *rsa.PrivateKey, pubPem string, fp string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.WriteHeader(200)
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, 405, []byte(`{"ok":false,"error":"method not allowed"}`))
			return
		}

		// добавим сразу несколько полей, чтобы UI точно подошло
		resp := `{"ok":true,"publicKey":` + jsonQuote(pubPem) +
			`,"publicKeyPem":` + jsonQuote(pubPem) +
			`,"fingerprint":` + jsonQuote(fp) + `}`
		writeJSON(w, 200, []byte(resp))
	}
}

func handlerRSADecrypt(priv *rsa.PrivateKey) http.HandlerFunc {
	type req struct {
		CiphertextB64 string `json:"ciphertextB64"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.WriteHeader(200)
			return
		}
		if r.Method != http.MethodPost {
			writeJSON(w, 405, []byte(`{"ok":false,"error":"method not allowed"}`))
			return
		}
		// простейший парс без зависимостей (можно заменить на json.NewDecoder)
		b, _ := io.ReadAll(r.Body)
		ctB64 := extractJSONField(string(b), "ciphertextB64")
		if ctB64 == "" {
			writeJSON(w, 400, []byte(`{"ok":false,"error":"ciphertextB64 required"}`))
			return
		}
		ct, err := base64.StdEncoding.DecodeString(ctB64)
		if err != nil {
			writeJSON(w, 400, []byte(`{"ok":false,"error":"bad base64"}`))
			return
		}

		plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ct, nil)
		if err != nil {
			writeJSON(w, 500, []byte(`{"ok":false,"error":"decrypt failed"}`))
			return
		}
		resp := `{"ok":true,"plaintextB64":` + jsonQuote(base64.StdEncoding.EncodeToString(plain)) + `}`
		writeJSON(w, 200, []byte(resp))
	}
}

// минимальные helper'ы, чтобы не тянуть лишние зависимости
func jsonQuote(s string) string {
	b := make([]byte, 0, len(s)+2)
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			b = append(b, '\\')
		}
		b = append(b, s[i])
	}
	b = append(b, '"')
	return string(b)
}
