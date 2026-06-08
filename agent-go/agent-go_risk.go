package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// pruneTimes keeps only timestamps within [now-window, now] and returns the pruned slice.
func pruneTimes(times []time.Time, window time.Duration, now time.Time) []time.Time {
	horizon := now.Add(-window)
	out := times[:0]
	for _, t := range times {
		if !t.Before(horizon) {
			out = append(out, t)
		}
	}
	return out
}

// countSince counts timestamps >= since.
func countSince(times []time.Time, since time.Time) int {
	n := 0
	for _, t := range times {
		if !t.Before(since) {
			n++
		}
	}
	return n
}

// pruneAssetMap removes entries whose timestamp < horizon. The map is modified in place.
func pruneAssetMap(m map[string]time.Time, horizon time.Time) {
	if m == nil {
		return
	}
	for k, t := range m {
		if t.Before(horizon) {
			delete(m, k)
		}
	}
}

type txSubmitter interface {
	SubmitTransaction(name string, args ...string) ([]byte, error)
}

// isBlockedNow returns whether local risk engine considers subject currently blocked.
// This is only used to throttle risk decisions between chaincode events; chaincode remains the source of truth.
func isBlockedNow(s *riskState, now time.Time) bool {
	if !s.IsBlocked {
		return false
	}
	if !s.BlockedUntil.IsZero() && now.After(s.BlockedUntil) {
		// local expiry (chaincode may also have expired)
		s.IsBlocked = false
		return false
	}
	return true
}

// pruneHistory keeps only entries newer than horizon.
func pruneHistory(times []time.Time, horizon time.Time) []time.Time {
	if times == nil {
		return []time.Time{}
	}
	out := times[:0]
	for _, t := range times {
		if !t.Before(horizon) {
			out = append(out, t)
		}
	}
	res := make([]time.Time, len(out))
	copy(res, out)
	return res
}

// calcBlockSeconds implements escalation:
// 1st -> 120s
// 2nd within 1h -> 600s
// 3rd within 24h -> 3600s
// 4+ within 24h -> 21600s
func calcBlockSeconds(s *riskState, now time.Time) int {
	// keep last 24h history
	s.BlockHistory = pruneHistory(s.BlockHistory, now.Add(-24*time.Hour))

	count24h := 0
	count1h := 0
	for _, t := range s.BlockHistory {
		if !t.Before(now.Add(-24 * time.Hour)) {
			count24h++
		}
		if !t.Before(now.Add(-1 * time.Hour)) {
			count1h++
		}
	}

	attempt24h := count24h + 1
	attempt1h := count1h + 1

	if attempt24h >= 4 {
		return 21600
	}
	if attempt24h == 3 {
		return 3600
	}
	if attempt1h >= 2 {
		return 600
	}
	return 120
}

// tryAutoBlock submits BlockUserForSeconds with escalation and cooldown.
func tryAutoBlock(contract txSubmitter, s *riskState, subject string, now time.Time, reason string) bool {
	// cooldown: avoid spamming ledger if we keep receiving events
	if !s.LastBlockAttempt.IsZero() && now.Sub(s.LastBlockAttempt) < 60*time.Second {
		return false
	}
	s.LastBlockAttempt = now

	if isBlockedNow(s, now) {
		return false
	}

	seconds := calcBlockSeconds(s, now)

	_, err := contract.SubmitTransaction("BlockUserForSeconds", subject, strconv.Itoa(seconds), reason)
	if err != nil {
		fmt.Printf("RISK: BlockUserForSeconds failed for %s: %v\n", short(subject, 18), err)
		return false
	}

	// update local state
	s.IsBlocked = true
	s.BlockedAt = now
	s.BlockedUntil = now.Add(time.Duration(seconds) * time.Second)
	s.BlockHistory = append(s.BlockHistory, now)

	fmt.Printf("RISK: ✅ Blocked user=%s seconds=%d reason=%s\n", short(subject, 18), seconds, reason)
	return true
}

type ChainEvent struct {
	Type      string `json:"type"`
	AssetID   string `json:"assetID"`
	ActorID   string `json:"actorID"`
	TargetID  string `json:"targetID"`
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Detail    string `json:"detail"`
}

type riskState struct {
	// rolling event timestamps
	DeniedTimes   []time.Time
	NotFoundTimes []time.Time
	KeyFetchTimes []time.Time
	DownloadTimes []time.Time

	// last-seen timestamps per asset for uniqueness
	DeniedAssets   map[string]time.Time
	NotFoundAssets map[string]time.Time
	KeyFetchAssets map[string]time.Time
	DownloadAssets map[string]time.Time

	// sync / status
	LastEventAt time.Time

	// local view of block status (to throttle / escalate). Chaincode is source of truth.
	IsBlocked    bool
	BlockedAt    time.Time
	BlockedUntil time.Time

	// local strike history to escalate block duration
	BlockHistory []time.Time

	// throttling: avoid spamming ledger with block txs
	LastBlockAttempt time.Time
}

func newRiskState() *riskState {
	return &riskState{
		DeniedTimes:      []time.Time{},
		NotFoundTimes:    []time.Time{},
		KeyFetchTimes:    []time.Time{},
		DownloadTimes:    []time.Time{},
		DeniedAssets:     make(map[string]time.Time),
		NotFoundAssets:   make(map[string]time.Time),
		KeyFetchAssets:   make(map[string]time.Time),
		DownloadAssets:   make(map[string]time.Time),
		BlockHistory:     []time.Time{},
		BlockedUntil:     time.Time{},
		LastBlockAttempt: time.Time{},
	}
}

// ensure state is fully initialized (protects from old/broken state instances).
func ensureRiskState(s *riskState) {
	if s.DeniedTimes == nil {
		s.DeniedTimes = []time.Time{}
	}
	if s.NotFoundTimes == nil {
		s.NotFoundTimes = []time.Time{}
	}
	if s.KeyFetchTimes == nil {
		s.KeyFetchTimes = []time.Time{}
	}
	if s.DownloadTimes == nil {
		s.DownloadTimes = []time.Time{}
	}
	if s.DeniedAssets == nil {
		s.DeniedAssets = make(map[string]time.Time)
	}
	if s.NotFoundAssets == nil {
		s.NotFoundAssets = make(map[string]time.Time)
	}
	if s.KeyFetchAssets == nil {
		s.KeyFetchAssets = make(map[string]time.Time)
	}
	if s.DownloadAssets == nil {
		s.DownloadAssets = make(map[string]time.Time)
	}
	if s.BlockHistory == nil {
		s.BlockHistory = []time.Time{}
	}
}

type riskEngine struct {
	mu     sync.Mutex
	states map[string]*riskState
}

func newRiskEngine() *riskEngine {
	return &riskEngine{states: make(map[string]*riskState)}
}

func (re *riskEngine) get(user string) *riskState {
	re.mu.Lock()
	defer re.mu.Unlock()

	s, ok := re.states[user]
	if !ok || s == nil {
		s = newRiskState()
		re.states[user] = s
		return s
	}

	ensureRiskState(s)
	return s
}

func (re *riskEngine) reset(user string) {
	re.mu.Lock()
	defer re.mu.Unlock()

	// Reset rolling windows, but keep BlockHistory for escalation within 24h.
	prev, ok := re.states[user]
	var hist []time.Time
	var lastAttempt time.Time
	if ok && prev != nil {
		hist = prev.BlockHistory
		lastAttempt = prev.LastBlockAttempt
	}

	ns := newRiskState()
	ns.BlockHistory = hist
	ns.LastBlockAttempt = lastAttempt
	re.states[user] = ns
}

// Возвращает (shouldBlock, score, reason)
func evalRisk(s *riskState, now time.Time) (bool, float64, string) {
	ensureRiskState(s)

	// чистим события по окнам
	s.DeniedTimes = pruneTimes(s.DeniedTimes, 5*time.Minute, now)
	s.NotFoundTimes = pruneTimes(s.NotFoundTimes, 2*time.Minute, now)
	s.KeyFetchTimes = pruneTimes(s.KeyFetchTimes, 2*time.Minute, now)
	s.DownloadTimes = pruneTimes(s.DownloadTimes, 5*time.Minute, now)

	// чистим карты уникальных ассетов по тем же окнам (иначе uniq* будет расти навечно)
	pruneAssetMap(s.DeniedAssets, now.Add(-5*time.Minute))
	pruneAssetMap(s.NotFoundAssets, now.Add(-2*time.Minute))
	pruneAssetMap(s.KeyFetchAssets, now.Add(-2*time.Minute))
	pruneAssetMap(s.DownloadAssets, now.Add(-5*time.Minute))

	den5m := countSince(s.DeniedTimes, now.Add(-5*time.Minute))
	den30s := countSince(s.DeniedTimes, now.Add(-30*time.Second))
	nf2m := countSince(s.NotFoundTimes, now.Add(-2*time.Minute))
	nf30s := countSince(s.NotFoundTimes, now.Add(-30*time.Second))
	key2m := countSince(s.KeyFetchTimes, now.Add(-2*time.Minute))
	dl5m := countSince(s.DownloadTimes, now.Add(-5*time.Minute))

	uniqDenied := len(s.DeniedAssets)
	uniqNF := len(s.NotFoundAssets)
	uniqKey := len(s.KeyFetchAssets)
	uniqDL := len(s.DownloadAssets)

	score := 0.0

	// 1) Много отказов (ABAC и т.п.) — даже по одному ассету
	if den30s >= 5 && uniqDenied >= 1 {
		score += 1.0
	} else if den5m >= 10 && uniqDenied >= 1 {
		score += 0.90
	} else if den5m >= 5 && uniqDenied >= 1 {
		score += 0.75
	} else if den5m >= 3 && uniqDenied >= 1 {
		score += 0.40
	}

	// 2) Массовые "asset not found" — сканирование ID/энумерация
	if nf30s >= 15 && uniqNF >= 15 {
		score += 1.0
	} else if nf30s >= 12 && uniqNF >= 12 {
		score += 0.90
	} else if nf2m >= 20 && uniqNF >= 20 {
		score += 0.90
	} else if nf2m >= 15 && uniqNF >= 15 {
		score += 0.70
	}

	// 3) KEY_FETCH / ASSET_KEY_FETCHED (key2m, uniqKey)
	// Сильный сигнал: десятки запросов ключа за 2 минуты — даже по одному asset.
	// Поднимаем скор до уровня блокировки при «лавине» key-fetch.
	if key2m >= 30 {
		if uniqKey <= 1 {
			score += 0.95
		} else {
			score += 0.90
		}
	} else if key2m >= 20 {
		if uniqKey <= 1 {
			score += 0.85
		} else {
			score += 0.80
		}
	} else if key2m >= 15 {
		score += 0.70
	} else if key2m >= 10 {
		score += 0.55
	} else if key2m >= 5 {
		score += 0.25
	}

	// 4) Много скачиваний (даже по одному ассету)
	if dl5m >= 40 && uniqDL >= 10 {
		score += 1.0
	} else if dl5m >= 25 && uniqDL >= 5 {
		score += 0.90
	} else if dl5m >= 15 && uniqDL >= 3 {
		score += 0.80
	} else if dl5m >= 10 && uniqDL >= 1 {
		score += 0.85
	} else if dl5m >= 7 && uniqDL >= 1 {
		score += 0.80
	} else if dl5m >= 5 && uniqDL >= 1 {
		score += 0.45
	}

	if score > 1.0 {
		score = 1.0
	}

	// Блокируем, если высокий скор и есть «достаточное подтверждение»
	shouldBlock := false
	if score >= 0.80 {
		if (den5m >= 5 && uniqDenied >= 1) ||
			(den30s >= 5 && uniqDenied >= 1) ||
			(dl5m >= 7 && uniqDL >= 1) ||
			(dl5m >= 15 && uniqDL >= 3) ||
			(dl5m >= 25 && uniqDL >= 5) ||
			(key2m >= 25 && uniqKey >= 4) ||
			(key2m >= 18 && uniqKey >= 2) ||
			(key2m >= 15 && uniqKey >= 3) ||
			(key2m >= 20 && uniqKey <= 1) ||
			(nf30s >= 12 && uniqNF >= 12) ||
			(nf2m >= 25 && uniqNF >= 20) {
			shouldBlock = true
		}
	}

	reason := fmt.Sprintf(
		"risk:auto den5m=%d den30s=%d uniqDenied=%d nf2m=%d nf30s=%d uniqNF=%d key2m=%d uniqKey=%d dl5m=%d uniqDL=%d score=%.2f",
		den5m, den30s, uniqDenied, nf2m, nf30s, uniqNF, key2m, uniqKey, dl5m, uniqDL, score,
	)

	return shouldBlock, score, reason
}

func runRiskEngine(cfg AgentConfig) error {
	gw, closeFn, err := connectGateway(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = closeFn() }()

	network := gw.GetNetwork(cfg.Channel)
	contract := network.GetContract(cfg.Chaincode)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Ctrl+C -> stop
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nStopping risk engine...")
		cancel()
	}()

	events, err := network.ChaincodeEvents(ctx, cfg.Chaincode)
	if err != nil {
		return fmt.Errorf("subscribe chaincode events failed: %w", err)
	}

	engine := newRiskEngine()

	fmt.Printf("Risk engine running (user=%s). Listening events on channel=%s chaincode=%s\n",
		cfg.User, cfg.Channel, cfg.Chaincode)

	for {
		select {
		case <-ctx.Done():
			return nil

		case ev, ok := <-events:
			if !ok {
				return fmt.Errorf("event stream closed")
			}

			// Обрабатываем ключевые события (risk engine)
			// - ACCESS_DENIED: попытки обойти ABAC/политику
			// - ASSET_KEY_FETCHED: получение ключа (может быть массовым)
			// - ASSET_DOWNLOADED: массовые скачивания
			// - USER_BLOCKED: синхронизируем локальный флаг блокировки
			switch ev.EventName {
			case "ACCESS_DENIED":
				var payload ChainEvent
				if err := json.Unmarshal(ev.Payload, &payload); err != nil {
					fmt.Printf("RISK: bad ACCESS_DENIED payload: %v raw=%s\n", err, string(ev.Payload))
					continue
				}

				// Не учитываем DENIED из-за уже действующей блокировки (иначе будет зацикливание/накрутка)
				if strings.HasPrefix(strings.TrimSpace(payload.Detail), "USER_BLOCKED") {
					continue
				}

				// Учитываем только реальные сигналы:
				// - ABAC_POLICY_DENY: нарушение ABAC
				// - ASSET_NOT_FOUND: сканирование/подбор assetID
				detail := strings.TrimSpace(payload.Detail)
				if detail != "ABAC_POLICY_DENY" && detail != "ASSET_NOT_FOUND" {
					continue
				}

				subject := strings.TrimSpace(payload.TargetID)
				if subject == "" {
					continue
				}

				now := time.Now().UTC()
				s := engine.get(subject)

				if detail == "ABAC_POLICY_DENY" {
					s.DeniedTimes = append(s.DeniedTimes, now)
					if payload.AssetID != "" {
						s.DeniedAssets[payload.AssetID] = now
					}
				} else if detail == "ASSET_NOT_FOUND" {
					s.NotFoundTimes = append(s.NotFoundTimes, now)
					if payload.AssetID != "" {
						s.NotFoundAssets[payload.AssetID] = now
					}
				}
				s.LastEventAt = now

				shouldBlock, score, reason := evalRisk(s, now)
				fmt.Printf("RISK: subject=%s event=ACCESS_DENIED asset=%s detail=%s score=%.2f\n",
					short(subject, 18), payload.AssetID, payload.Detail, score)

				if !shouldBlock || isBlockedNow(s, now) {
					continue
				}

				if ok := tryAutoBlock(contract, s, subject, now, reason); !ok {
					continue
				}

			case "ASSET_KEY_FETCHED":
				var payload ChainEvent
				if err := json.Unmarshal(ev.Payload, &payload); err != nil {
					fmt.Printf("RISK: bad ASSET_KEY_FETCHED payload: %v raw=%s\n", err, string(ev.Payload))
					continue
				}
				subject := strings.TrimSpace(payload.ActorID)
				if subject == "" {
					continue
				}

				now := time.Now().UTC()
				s := engine.get(subject)
				s.KeyFetchTimes = append(s.KeyFetchTimes, now)
				if payload.AssetID != "" {
					s.KeyFetchAssets[payload.AssetID] = now
				}
				s.LastEventAt = now

				shouldBlock, score, reason := evalRisk(s, now)
				fmt.Printf("RISK: subject=%s event=KEY_FETCH asset=%s score=%.2f\n",
					short(subject, 18), payload.AssetID, score)

				if !shouldBlock || isBlockedNow(s, now) {
					continue
				}

				if ok := tryAutoBlock(contract, s, subject, now, reason); !ok {
					continue
				}

			case "ASSET_DOWNLOADED":
				var payload ChainEvent
				if err := json.Unmarshal(ev.Payload, &payload); err != nil {
					fmt.Printf("RISK: bad ASSET_DOWNLOADED payload: %v raw=%s\n", err, string(ev.Payload))
					continue
				}
				subject := strings.TrimSpace(payload.ActorID)
				if subject == "" {
					continue
				}

				now := time.Now().UTC()
				s := engine.get(subject)
				s.DownloadTimes = append(s.DownloadTimes, now)
				if payload.AssetID != "" {
					s.DownloadAssets[payload.AssetID] = now
				}
				s.LastEventAt = now

				shouldBlock, score, reason := evalRisk(s, now)
				fmt.Printf("RISK: subject=%s event=DOWNLOAD asset=%s score=%.2f\n",
					short(subject, 18), payload.AssetID, score)

				if !shouldBlock || isBlockedNow(s, now) {
					continue
				}

				if ok := tryAutoBlock(contract, s, subject, now, reason); !ok {
					continue
				}

			case "USER_UNBLOCKED":
				var payload ChainEvent
				if err := json.Unmarshal(ev.Payload, &payload); err != nil {
					fmt.Printf("RISK: bad USER_UNBLOCKED payload: %v raw=%s\n", err, string(ev.Payload))
					continue
				}
				subject := strings.TrimSpace(payload.TargetID)
				if subject != "" {
					engine.reset(subject)
					fmt.Printf("RISK: reset state for subject=%s after USER_UNBLOCKED\n", short(subject, 18))
				}

			case "USER_BLOCKED":
				var payload ChainEvent
				if json.Unmarshal(ev.Payload, &payload) == nil {
					subject := strings.TrimSpace(payload.TargetID)
					if subject != "" {
						s := engine.get(subject)
						s.IsBlocked = true
						s.BlockedAt = time.Now().UTC()
					}
				}

			default:
				continue
			}
		}
	}
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
