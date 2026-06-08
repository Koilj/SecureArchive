package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	gatewaypb "github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	"google.golang.org/protobuf/proto"
)

type offlineResult struct {
	ProposalBytesB64    string `json:"proposalBytesB64,omitempty"`
	ProposalSignB64     string `json:"proposalSignB64,omitempty"`
	TransactionBytesB64 string `json:"transactionBytesB64,omitempty"`
	TransactionSignB64  string `json:"transactionSignB64,omitempty"`
	TransactionID       string `json:"transactionID,omitempty"`
	ResultJSON          any    `json:"resultJSON,omitempty"`
	ResultText          string `json:"resultText,omitempty"`
}

func connectGatewayWithCert(cfg AgentConfig, certPEM []byte) (*client.Gateway, func() error, error) {
	clientConn, err := newGrpcConnection(cfg.PeerEndpoint, cfg.PeerHostAlias, peerTLSCertPath(cfg))
	if err != nil {
		return nil, nil, err
	}

	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		_ = clientConn.Close()
		return nil, nil, fmt.Errorf("parse signcert PEM: %w", err)
	}
	id, err := identity.NewX509Identity(cfg.MSPID, cert)
	if err != nil {
		_ = clientConn.Close()
		return nil, nil, fmt.Errorf("NewX509Identity: %w", err)
	}

	gw, err := client.Connect(
		id,
		client.WithHash(hash.SHA256),
		client.WithClientConnection(clientConn),
		client.WithEvaluateTimeout(5e9),
		client.WithEndorseTimeout(15e9),
		client.WithSubmitTimeout(15e9),
		client.WithCommitStatusTimeout(30e9),
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

func decodeCertArg(arg string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(arg)
}

func proposalSignInput(bytes []byte) ([]byte, error) {
	msg := &gatewaypb.ProposedTransaction{}
	if err := proto.Unmarshal(bytes, msg); err != nil {
		return nil, err
	}
	return msg.GetProposal().GetProposalBytes(), nil
}

func transactionSignInput(bytes []byte) ([]byte, error) {
	msg := &gatewaypb.PreparedTransaction{}
	if err := proto.Unmarshal(bytes, msg); err != nil {
		return nil, err
	}
	envelope := msg.GetEnvelope()
	if envelope == nil {
		return nil, fmt.Errorf("transaction envelope missing")
	}
	payload := envelope.GetPayload()
	if len(payload) == 0 {
		return nil, fmt.Errorf("transaction payload missing")
	}
	return payload, nil
}

func setResultBytes(out *offlineResult, result []byte) {
	if len(result) == 0 {
		return
	}
	var parsed any
	if err := json.Unmarshal(result, &parsed); err == nil {
		out.ResultJSON = parsed
		return
	}
	out.ResultText = string(result)
}

func offlinePrepareProposal(cfg AgentConfig, certPEM []byte, fn string, args []string) error {
	gw, closeFn, err := connectGatewayWithCert(cfg, certPEM)
	if err != nil {
		return err
	}
	defer func() { _ = closeFn() }()

	contract := gw.GetNetwork(cfg.Channel).GetContract(cfg.Chaincode)
	proposal, err := contract.NewProposal(fn, client.WithArguments(args...))
	if err != nil {
		return err
	}
	proposalBytes, err := proposal.Bytes()
	if err != nil {
		return err
	}
	signInput, err := proposalSignInput(proposalBytes)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdoutWriter{}).Encode(offlineResult{
		ProposalBytesB64: base64.StdEncoding.EncodeToString(proposalBytes),
		ProposalSignB64:  base64.StdEncoding.EncodeToString(signInput),
		TransactionID:    proposal.TransactionID(),
	})
}

func offlineEvaluateSigned(cfg AgentConfig, certPEM []byte, proposalBytesB64 string, signatureB64 string) error {
	gw, closeFn, err := connectGatewayWithCert(cfg, certPEM)
	if err != nil {
		return err
	}
	defer func() { _ = closeFn() }()

	proposalBytes, err := base64.StdEncoding.DecodeString(proposalBytesB64)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return err
	}
	proposal, err := gw.NewSignedProposal(proposalBytes, signature)
	if err != nil {
		return err
	}
	result, err := proposal.Evaluate()
	if err != nil {
		return err
	}
	out := offlineResult{TransactionID: proposal.TransactionID()}
	setResultBytes(&out, result)
	return json.NewEncoder(stdoutWriter{}).Encode(out)
}

func offlineEndorseSigned(cfg AgentConfig, certPEM []byte, proposalBytesB64 string, signatureB64 string) error {
	gw, closeFn, err := connectGatewayWithCert(cfg, certPEM)
	if err != nil {
		return err
	}
	defer func() { _ = closeFn() }()

	proposalBytes, err := base64.StdEncoding.DecodeString(proposalBytesB64)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return err
	}
	proposal, err := gw.NewSignedProposal(proposalBytes, signature)
	if err != nil {
		return err
	}
	transaction, err := proposal.Endorse()
	if err != nil {
		return err
	}
	transactionBytes, err := transaction.Bytes()
	if err != nil {
		return err
	}
	signInput, err := transactionSignInput(transactionBytes)
	if err != nil {
		return err
	}
	out := offlineResult{
		TransactionBytesB64: base64.StdEncoding.EncodeToString(transactionBytes),
		TransactionSignB64:  base64.StdEncoding.EncodeToString(signInput),
		TransactionID:       transaction.TransactionID(),
	}
	setResultBytes(&out, transaction.Result())
	return json.NewEncoder(stdoutWriter{}).Encode(out)
}

func offlineSubmitSigned(cfg AgentConfig, certPEM []byte, transactionBytesB64 string, signatureB64 string) error {
	gw, closeFn, err := connectGatewayWithCert(cfg, certPEM)
	if err != nil {
		return err
	}
	defer func() { _ = closeFn() }()

	transactionBytes, err := base64.StdEncoding.DecodeString(transactionBytesB64)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return err
	}
	transaction, err := gw.NewSignedTransaction(transactionBytes, signature)
	if err != nil {
		return err
	}
	if _, err := transaction.Submit(); err != nil {
		return err
	}
	out := offlineResult{TransactionID: transaction.TransactionID()}
	setResultBytes(&out, transaction.Result())
	return json.NewEncoder(stdoutWriter{}).Encode(out)
}

type stdoutWriter struct{}

func (stdoutWriter) Write(p []byte) (int, error) {
	return fmt.Print(string(p))
}
