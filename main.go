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
	// Локальный HTTP-агент
	if len(os.Args) >= 2 && os.Args[1] == "serve" {
		serveHTTP()
		return
	}

	// Listener chaincode events (debug)
	if len(os.Args) >= 2 && os.Args[1] == "listen" {
		fabricPath := os.Getenv("FABRIC_PATH")
		if fabricPath == "" {
			fmt.Println("ERROR: set FABRIC_PATH env var (path to fabric-samples/test-network)")
			os.Exit(1)
		}

		cfg := AgentConfig{
			FabricPath:    fabricPath,
			Org:           envOr("AGENT_ORG", "org1"),
			User:          envOr("AGENT_USER", "Ruslan"),
			Channel:       envOr("AGENT_CHANNEL", "mychannel"),
			Chaincode:     envOr("AGENT_CHAINCODE", "securedata"),
			PeerEndpoint:  envOr("AGENT_PEER_ENDPOINT", "localhost:7051"),
			PeerHostAlias: envOr("AGENT_PEER_HOST", "peer0.org1.example.com"),
			MSPID:         envOr("AGENT_MSPID", "Org1MSP"),
		}

		if err := listenEvents(cfg); err != nil {
			fmt.Printf("LISTEN ERROR: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Risk engine (RiskService)
	if len(os.Args) >= 2 && os.Args[1] == "risk" {
		fabricPath := os.Getenv("FABRIC_PATH")
		if fabricPath == "" {
			fmt.Println("ERROR: set FABRIC_PATH env var (path to fabric-samples/test-network)")
			os.Exit(1)
		}

		cfg := AgentConfig{
			FabricPath:    fabricPath,
			Org:           envOr("AGENT_ORG", "org1"),
			User:          envOr("AGENT_USER", "RiskService"),
			Channel:       envOr("AGENT_CHANNEL", "mychannel"),
			Chaincode:     envOr("AGENT_CHAINCODE", "securedata"),
			PeerEndpoint:  envOr("AGENT_PEER_ENDPOINT", "localhost:7051"),
			PeerHostAlias: envOr("AGENT_PEER_HOST", "peer0.org1.example.com"),
			MSPID:         envOr("AGENT_MSPID", "Org1MSP"),
		}

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

	mode := os.Args[1] // eval | submit
	fn := os.Args[2]
	args := []string{}
	if len(os.Args) > 3 {
		args = os.Args[3:]
	}

	fabricPath := os.Getenv("FABRIC_PATH")
	if fabricPath == "" {
		fmt.Println("ERROR: set FABRIC_PATH env var (path to fabric-samples/test-network)")
		os.Exit(1)
	}

	cfg := AgentConfig{
		FabricPath:    fabricPath,
		Org:           envOr("AGENT_ORG", "org1"),
		User:          envOr("AGENT_USER", "Ruslan"),
		Channel:       envOr("AGENT_CHANNEL", "mychannel"),
		Chaincode:     envOr("AGENT_CHAINCODE", "securedata"),
		PeerEndpoint:  envOr("AGENT_PEER_ENDPOINT", "localhost:7051"),
		PeerHostAlias: envOr("AGENT_PEER_HOST", "peer0.org1.example.com"),
		MSPID:         envOr("AGENT_MSPID", "Org1MSP"),
	}

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
	fmt.Println("  go run . serve")
	fmt.Println("  go run . listen")
	fmt.Println("  go run . risk")
	fmt.Println("  go run . eval <TxName> [args...]")
	fmt.Println("  go run . submit <TxName> [args...]")
	fmt.Println("")
	fmt.Println("Env:")
	fmt.Println("  FABRIC_PATH=/path/to/fabric-samples/test-network")
	fmt.Println("  AGENT_ORG=org1|org2")
	fmt.Println("  AGENT_USER=Ruslan|Ersultan|SecurityService")
	fmt.Println("  AGENT_MSPID=Org1MSP|Org2MSP")
	fmt.Println("  AGENT_PEER_ENDPOINT=localhost:7051 (org1) or localhost:9051 (org2)")
	fmt.Println("  AGENT_PEER_HOST=peer0.org1.example.com")
	fmt.Println("  AGENT_CHANNEL=mychannel")
	fmt.Println("  AGENT_CHAINCODE=securedata")
	fmt.Println("  AGENT_HTTP_ADDR=127.0.0.1:8088")
}
