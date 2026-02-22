package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
)

func ListenEvents() error {
	// 1) Берём конфиг так же, как для submit/eval
	cfg := loadConfigFromEnv()

	// 2) Коннектимся к gateway
	gw, closeFn, err := connectGateway(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = closeFn() }()

	network := gw.GetNetwork(cfg.Channel)

	// 3) Контекст + Ctrl+C
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nStopping listener...")
		cancel()
	}()

	// 4) Подписка на события chaincode
	events, err := network.ChaincodeEvents(ctx, cfg.Chaincode)
	if err != nil {
		return fmt.Errorf("subscribe chaincode events failed: %w", err)
	}

	fmt.Printf("Listening chaincode events: channel=%s chaincode=%s (Ctrl+C to stop)\n", cfg.Channel, cfg.Chaincode)

	// 5) Читаем поток и печатаем
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

			// payload пробуем разобрать как JSON
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

// loadConfigFromEnv — добавим в fabric.go (см. шаг 2)
func loadConfigFromEnv() AgentConfig {
	fabricPath := os.Getenv("FABRIC_PATH")
	if fabricPath == "" {
		// чтобы ошибки были понятные
		panic("FABRIC_PATH env var is not set")
	}

	org := os.Getenv("AGENT_ORG")
	if org == "" {
		org = "org1"
	}
	user := os.Getenv("AGENT_USER")
	if user == "" {
		user = "User1"
	}
	mspid := os.Getenv("AGENT_MSPID")
	if mspid == "" {
		// дефолт под org
		if org == "org1" {
			mspid = "Org1MSP"
		} else if org == "org2" {
			mspid = "Org2MSP"
		} else {
			mspid = "Org1MSP"
		}
	}

	channel := os.Getenv("CHANNEL_NAME")
	if channel == "" {
		channel = "mychannel"
	}
	chaincode := os.Getenv("CHAINCODE_NAME")
	if chaincode == "" {
		chaincode = "securedata"
	}

	peerEndpoint := os.Getenv("AGENT_PEER_ENDPOINT")
	if peerEndpoint == "" {
		peerEndpoint = "localhost:7051"
	}
	peerHost := os.Getenv("AGENT_PEER_HOST")
	if peerHost == "" {
		peerHost = "peer0.org1.example.com"
	}

	return AgentConfig{
		FabricPath:    fabricPath,
		Org:           org,
		User:          user,
		Channel:       channel,
		Chaincode:     chaincode,
		PeerEndpoint:  peerEndpoint,
		PeerHostAlias: peerHost,
		MSPID:         mspid,
	}
}

// чтобы go не ругался на неиспользуемый импорт client (иногда IDE делает)
// это не обязательно, но оставлю безопасно:
var _ *client.Gateway
