package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// Единый HTTP-агент с мульти-идентичностью (SecurityService + MLService + ...)
	if len(os.Args) >= 2 && os.Args[1] == "serve-unified" {
		serveUnifiedHTTP()
		return
	}

	// Локальный HTTP-агент (одна идентичность, обратная совместимость)
	if len(os.Args) >= 2 && os.Args[1] == "serve" {
		serveHTTP()
		return
	}

	// Listener chaincode events (debug)
	if len(os.Args) >= 2 && os.Args[1] == "listen" {
		cfg := defaultAgentConfig("SecurityService")

		if err := listenEvents(cfg); err != nil {
			fmt.Printf("LISTEN ERROR: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Risk engine (RiskService)
	if len(os.Args) >= 2 && os.Args[1] == "risk" {
		cfg := defaultAgentConfig("RiskService")

		if err := runRiskEngine(cfg); err != nil {
			fmt.Printf("RISK ERROR: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// CLI-режим: eval/submit
	if len(os.Args) < 3 {
		usage()
		os.Exit(2)
	}

	if len(os.Args) >= 4 {
		mode := os.Args[1]
		certB64 := os.Args[2]
		switch mode {
		case "offline-prepare-eval":
			cfg := defaultAgentConfig("SecurityService")
			certPEM, err := decodeCertArg(certB64)
			if err != nil {
				fmt.Printf("OFFLINE ERROR: %v\n", err)
				os.Exit(1)
			}
			if err := offlinePrepareProposal(cfg, certPEM, os.Args[3], os.Args[4:]); err != nil {
				fmt.Printf("OFFLINE ERROR: %v\n", err)
				os.Exit(1)
			}
			return
		case "offline-evaluate-signed":
			if len(os.Args) < 5 {
				usage()
				os.Exit(2)
			}
			cfg := defaultAgentConfig("SecurityService")
			certPEM, err := decodeCertArg(certB64)
			if err != nil {
				fmt.Printf("OFFLINE ERROR: %v\n", err)
				os.Exit(1)
			}
			if err := offlineEvaluateSigned(cfg, certPEM, os.Args[3], os.Args[4]); err != nil {
				fmt.Printf("OFFLINE ERROR: %v\n", err)
				os.Exit(1)
			}
			return
		case "offline-endorse-signed":
			if len(os.Args) < 5 {
				usage()
				os.Exit(2)
			}
			cfg := defaultAgentConfig("SecurityService")
			certPEM, err := decodeCertArg(certB64)
			if err != nil {
				fmt.Printf("OFFLINE ERROR: %v\n", err)
				os.Exit(1)
			}
			if err := offlineEndorseSigned(cfg, certPEM, os.Args[3], os.Args[4]); err != nil {
				fmt.Printf("OFFLINE ERROR: %v\n", err)
				os.Exit(1)
			}
			return
		case "offline-submit-signed":
			if len(os.Args) < 5 {
				usage()
				os.Exit(2)
			}
			cfg := defaultAgentConfig("SecurityService")
			certPEM, err := decodeCertArg(certB64)
			if err != nil {
				fmt.Printf("OFFLINE ERROR: %v\n", err)
				os.Exit(1)
			}
			if err := offlineSubmitSigned(cfg, certPEM, os.Args[3], os.Args[4]); err != nil {
				fmt.Printf("OFFLINE ERROR: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	mode := os.Args[1] // eval | submit
	fn := os.Args[2]
	args := []string{}
	if len(os.Args) > 3 {
		args = os.Args[3:]
	}

	cfg := defaultAgentConfig("SecurityService")

	gw, closeFn, err := connectGateway(cfg)
	if err != nil {
		fmt.Printf("CONNECT ERROR: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = closeFn() }()

	network := gw.GetNetwork(cfg.Channel)
	contract := network.GetContract(cfg.Chaincode)

	switch mode {
	case "eval":
		res, err := contract.EvaluateTransaction(fn, args...)
		if err != nil {
			fmt.Printf("EVAL ERROR: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s\n", string(res))

	case "submit":
		res, err := contract.SubmitTransaction(fn, args...)
		if err != nil {
			fmt.Printf("SUBMIT ERROR: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s\n", string(res))

	default:
		usage()
		os.Exit(2)
	}
}

func fabricPathOrExit() string {
	fabricPath := os.Getenv("FABRIC_PATH")
	if fabricPath == "" {
		fmt.Println("ERROR: set FABRIC_PATH env var (path to fabric-samples/test-network)")
		os.Exit(1)
	}
	return fabricPath
}

func defaultAgentConfig(defaultUser string) AgentConfig {
	return AgentConfig{
		FabricPath:    fabricPathOrExit(),
		Org:           envOr("AGENT_ORG", "org1"),
		User:          envOr("AGENT_USER", defaultUser),
		Channel:       envOr("AGENT_CHANNEL", "mychannel"),
		Chaincode:     envOr("AGENT_CHAINCODE", "securedata"),
		PeerEndpoint:  envOr("AGENT_PEER_ENDPOINT", "localhost:7051"),
		PeerHostAlias: envOr("AGENT_PEER_HOST", "peer0.org1.example.com"),
		MSPID:         envOr("AGENT_MSPID", "Org1MSP"),
	}
}

func listenEvents(cfg AgentConfig) error {
	gw, closeFn, err := connectGateway(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = closeFn() }()

	network := gw.GetNetwork(cfg.Channel)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Ctrl+C -> stop
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nStopping listener...")
		cancel()
	}()

	events, err := network.ChaincodeEvents(ctx, cfg.Chaincode)
	if err != nil {
		return fmt.Errorf("subscribe chaincode events failed: %w", err)
	}

	fmt.Printf("Listening chaincode events: channel=%s chaincode=%s (Ctrl+C to stop)\n", cfg.Channel, cfg.Chaincode)

	for {
		select {
		case <-ctx.Done():
			return nil

		case ev, ok := <-events:
			if !ok {
				return fmt.Errorf("event stream closed")
			}

			out := map[string]any{
				"eventName":   ev.EventName,
				"txID":        ev.TransactionID,
				"blockNumber": ev.BlockNumber,
				"receivedAt":  time.Now().UTC().Format(time.RFC3339),
			}

			// payload пытаемся распарсить как JSON
			var payload any
			if len(ev.Payload) > 0 && json.Unmarshal(ev.Payload, &payload) == nil {
				out["payload"] = payload
			} else {
				out["payloadRaw"] = string(ev.Payload)
			}

			b, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(b))
		}
	}
}

func envOr(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func usage() {
	fmt.Println("Usage:")
	fmt.Println("  go run . serve-unified                (recommended: multi-identity single process)")
	fmt.Println("  go run . serve                        (legacy: single-identity HTTP agent)")
	fmt.Println("  go run . listen")
	fmt.Println("  go run . risk")
	fmt.Println("  go run . offline-prepare-eval <certB64> <TxName> [args...]")
	fmt.Println("  go run . offline-evaluate-signed <certB64> <proposalBytesB64> <signatureB64>")
	fmt.Println("  go run . offline-endorse-signed <certB64> <proposalBytesB64> <signatureB64>")
	fmt.Println("  go run . offline-submit-signed <certB64> <transactionBytesB64> <signatureB64>")
	fmt.Println("  go run . eval <TxName> [args...]")
	fmt.Println("  go run . submit <TxName> [args...]")
	fmt.Println("")
	fmt.Println("Env:")
	fmt.Println("  FABRIC_PATH=/path/to/fabric-samples/test-network")
	fmt.Println("  AGENT_ORG=org1|org2")
	fmt.Println("  AGENT_USER=SecurityService|MLService|RiskService|<custom username>")
	fmt.Println("  AGENT_MSPID=Org1MSP|Org2MSP")
	fmt.Println("  AGENT_PEER_ENDPOINT=localhost:7051 (org1) or localhost:9051 (org2)")
	fmt.Println("  AGENT_PEER_HOST=peer0.org1.example.com")
	fmt.Println("  AGENT_CHANNEL=mychannel")
	fmt.Println("  AGENT_CHAINCODE=securedata")
	fmt.Println("  AGENT_HTTP_ADDR=127.0.0.1:8090")
	fmt.Println("  AGENT_IDENTITIES=SecurityService,MLService  (for serve-unified)")
}
