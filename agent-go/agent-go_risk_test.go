package main

import (
	"testing"
	"time"
)

func TestPruneTimesAndCountSince(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	pts := []time.Time{
		now.Add(-10 * time.Minute),
		now.Add(-3 * time.Minute),
		now.Add(-30 * time.Second),
		now,
	}
	// window = 5m => keep last three
	pruned := pruneTimes(append([]time.Time(nil), pts...), 5*time.Minute, now)
	if len(pruned) != 3 {
		t.Fatalf("expected 3 pruned timestamps, got %d", len(pruned))
	}

	// countSince last minute => only -30s and now
	if n := countSince(pts, now.Add(-time.Minute)); n != 2 {
		t.Fatalf("expected 2 events in last minute, got %d", n)
	}
}

func TestPruneAssetMap(t *testing.T) {
	now := time.Now().UTC()
	m := map[string]time.Time{
		"a": now.Add(-10 * time.Minute),
		"b": now.Add(-30 * time.Second),
		"c": now,
	}
	pruneAssetMap(m, now.Add(-2*time.Minute))
	if _, ok := m["a"]; ok {
		t.Fatalf("expected key 'a' to be pruned")
	}
	if _, ok := m["b"]; !ok {
		t.Fatalf("expected key 'b' to survive")
	}
	if _, ok := m["c"]; !ok {
		t.Fatalf("expected key 'c' to survive")
	}
}

func TestCalcBlockSecondsEscalation(t *testing.T) {
	now := time.Now().UTC()
	s := newRiskState()

	// 1st block -> 120s
	if got := calcBlockSeconds(s, now); got != 120 {
		t.Fatalf("first block: want 120, got %d", got)
	}
	s.BlockHistory = append(s.BlockHistory, now)

	// 2nd block within 1h -> 600s
	if got := calcBlockSeconds(s, now.Add(10*time.Minute)); got != 600 {
		t.Fatalf("second block within 1h: want 600, got %d", got)
	}
	s.BlockHistory = append(s.BlockHistory, now.Add(10*time.Minute))

	// 3rd block within 24h -> 3600s
	if got := calcBlockSeconds(s, now.Add(2*time.Hour)); got != 3600 {
		t.Fatalf("third block within 24h: want 3600, got %d", got)
	}
	s.BlockHistory = append(s.BlockHistory, now.Add(2*time.Hour))

	// 4th within 24h -> 21600s
	if got := calcBlockSeconds(s, now.Add(3*time.Hour)); got != 21600 {
		t.Fatalf("fourth block within 24h: want 21600, got %d", got)
	}
}

func TestEvalRiskDownloadBurst(t *testing.T) {
	now := time.Now().UTC()
	s := newRiskState()
	// 10 downloads of a single asset within the 5-minute window triggers block.
	for i := 0; i < 10; i++ {
		s.DownloadTimes = append(s.DownloadTimes, now.Add(time.Duration(-i)*time.Second))
	}
	s.DownloadAssets["asset-1"] = now

	shouldBlock, score, reason := evalRisk(s, now)
	if !shouldBlock {
		t.Fatalf("expected risk engine to request block (score=%.2f, reason=%q)", score, reason)
	}
	if score <= 0.80 {
		t.Fatalf("expected score > 0.80, got %.2f", score)
	}
}

func TestEvalRiskKeyFetchAvalanche(t *testing.T) {
	now := time.Now().UTC()
	s := newRiskState()
	for i := 0; i < 30; i++ {
		s.KeyFetchTimes = append(s.KeyFetchTimes, now.Add(time.Duration(-i)*time.Second))
	}
	s.KeyFetchAssets["a-1"] = now

	shouldBlock, score, _ := evalRisk(s, now)
	if !shouldBlock {
		t.Fatalf("expected block for key-fetch avalanche (score=%.2f)", score)
	}
}

func TestEvalRiskLowTrafficDoesNotBlock(t *testing.T) {
	now := time.Now().UTC()
	s := newRiskState()
	s.DownloadTimes = []time.Time{now.Add(-10 * time.Second)}
	s.DownloadAssets["asset-1"] = now.Add(-10 * time.Second)

	shouldBlock, _, _ := evalRisk(s, now)
	if shouldBlock {
		t.Fatalf("expected no block for a single download")
	}
}

func TestIsBlockedNowExpires(t *testing.T) {
	now := time.Now().UTC()
	s := newRiskState()
	s.IsBlocked = true
	s.BlockedUntil = now.Add(-1 * time.Second)

	if isBlockedNow(s, now) {
		t.Fatalf("expected stale block to be cleared")
	}
	if s.IsBlocked {
		t.Fatalf("expected IsBlocked to flip to false after expiry")
	}
}
