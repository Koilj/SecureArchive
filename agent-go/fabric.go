package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type AgentConfig struct {
	FabricPath    string
	Org           string
	User          string
	Channel       string
	Chaincode     string
	PeerEndpoint  string
	PeerHostAlias string
	MSPID         string
}

func connectGateway(cfg AgentConfig) (*client.Gateway, func() error, error) {
	if cfg.FabricPath == "" {
		return nil, nil, fmt.Errorf("FABRIC_PATH is empty")
	}

	tlsCertPath := peerTLSCertPath(cfg)
	clientConn, err := newGrpcConnection(cfg.PeerEndpoint, cfg.PeerHostAlias, tlsCertPath)
	if err != nil {
		return nil, nil, err
	}

	id, sign, err := newIdentityAndSign(cfg)
	if err != nil {
		_ = clientConn.Close()
		return nil, nil, err
	}

	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithHash(hash.SHA256),
		client.WithClientConnection(clientConn),
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(15*time.Second),
		client.WithCommitStatusTimeout(30*time.Second),
	)
	if err != nil {
		_ = clientConn.Close()
		return nil, nil, fmt.Errorf("client.Connect failed: %w", err)
	}

	closeFn := func() error {
		gw.Close()
		return clientConn.Close()
	}
	return gw, closeFn, nil
}

func newGrpcConnection(peerEndpoint, peerHostAlias, tlsCertPath string) (*grpc.ClientConn, error) {
	tlsPem, err := os.ReadFile(tlsCertPath)
	if err != nil {
		return nil, fmt.Errorf("read tls cert: %w (path=%s)", err, tlsCertPath)
	}

	tlsCert, err := identity.CertificateFromPEM(tlsPem)
	if err != nil {
		return nil, fmt.Errorf("parse tls cert PEM: %w", err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(tlsCert)

	creds := credentials.NewClientTLSFromCert(certPool, peerHostAlias)
	conn, err := grpc.Dial(peerEndpoint, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("grpc dial %s: %w", peerEndpoint, err)
	}
	return conn, nil
}

func newIdentityAndSign(cfg AgentConfig) (*identity.X509Identity, identity.Sign, error) {
	mspDir := userMSPDir(cfg)

	certPath, err := firstFile(filepath.Join(mspDir, "signcerts"), ".pem")
	if err != nil {
		return nil, nil, fmt.Errorf("find signcert: %w", err)
	}

	keyPath, err := firstFile(filepath.Join(mspDir, "keystore"), "")
	if err != nil {
		return nil, nil, fmt.Errorf("find keystore key: %w", err)
	}

	certPem, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read signcert: %w", err)
	}
	cert, err := identity.CertificateFromPEM(certPem)
	if err != nil {
		return nil, nil, fmt.Errorf("parse signcert: %w", err)
	}

	id, err := identity.NewX509Identity(cfg.MSPID, cert)
	if err != nil {
		return nil, nil, fmt.Errorf("NewX509Identity: %w", err)
	}

	keyPem, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read private key: %w", err)
	}
	privateKey, err := identity.PrivateKeyFromPEM(keyPem)
	if err != nil {
		return nil, nil, fmt.Errorf("PrivateKeyFromPEM: %w", err)
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("NewPrivateKeySign: %w", err)
	}

	return id, sign, nil
}

func userMSPDir(cfg AgentConfig) string {
	if v := strings.TrimSpace(os.Getenv("AGENT_MSP_DIR")); v != "" {
		return v
	}
	domain := fmt.Sprintf("%s.example.com", cfg.Org)
	return filepath.Join(
		cfg.FabricPath,
		"organizations",
		"peerOrganizations",
		domain,
		"users",
		fmt.Sprintf("%s@%s", cfg.User, domain),
		"msp",
	)
}

func peerTLSCertPath(cfg AgentConfig) string {
	domain := fmt.Sprintf("%s.example.com", cfg.Org)
	peer := fmt.Sprintf("peer0.%s", domain)
	return filepath.Join(
		cfg.FabricPath,
		"organizations",
		"peerOrganizations",
		domain,
		"peers",
		peer,
		"tls",
		"ca.crt",
	)
}

func firstFile(dir, ext string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("readdir %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if ext == "" || strings.HasSuffix(strings.ToLower(name), strings.ToLower(ext)) {
			return filepath.Join(dir, name), nil
		}
	}
	return "", fmt.Errorf("no file found in %s with ext=%q", dir, ext)
}
