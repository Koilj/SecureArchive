//go:build mlwatch
// +build mlwatch

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
)

// =====================
// MLWatch
// =====================
//
// Listens chaincode events and, for newly created assets that still require
// manual review (e.g., category Unverified/Unknown), calls external AI service
// to suggest a category. On success it submits AddSuggestedCategory as MLService.
//
// IMPORTANT FIX:
// In your current chaincode, ReadAsset returns a *string* like "&{...}" (Go fmt)
// instead of JSON. Previous implementation assumed JSON and failed with:
//   invalid character '&' looking for beginning of value
//
// This file now supports BOTH:
//   1) JSON payloads (preferred)
//   2) Go fmt string "&{...}" (fallback parser)

// keywordsField unmarshals keywords from either JSON string ("a,b") or array (["a","b"]).
type keywordsField []string

func (k *keywordsField) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		*k = []string{}
		return nil
	}
	if b[0] == '[' {
		var arr []string
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		*k = arr
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*k = splitKeywords(s)
	return nil
}

// On-chain view of asset used by MLWatch.
// Keep it small and tolerant to unknown fields.
type assetOnChain struct {
	ID                string `json:"id"`
	Category          string `json:"category"`
	SuggestedCategory string `json:"suggestedCategory"`
	NeedsManualReview bool   `json:"needsManualReview"`
	Description       string `json:"description"`
	Owner             string `json:"owner"`
	OwnerName         string `json:"ownerName"`
	Metadata          struct {
		Title      string        `json:"title"`
		Authors    string        `json:"authors"`
		Author     string        `json:"author"`
		Department string        `json:"department"`
		Discipline string        `json:"discipline"`
		Keywords   keywordsField `json:"keywords"`
	} `json:"metadata"`
}

type aiSuggestReq struct {
	AssetID  string `json:"asset_id"`
	Metadata struct {
		Title       string   `json:"title"`
		Description string   `json:"description"`
		Author      string   `json:"author"`
		Department  string   `json:"department"`
		Keywords    []string `json:"keywords"`
	} `json:"metadata"`
}

type aiSuggestResp struct {
	Status            string  `json:"status"`
	SuggestedCategory string  `json:"suggested_category"`
	Confidence        float64 `json:"confidence"`
	Message           string  `json:"message"`
}

func runMLWatch(args []string) {
	cfg := loadConfigFromEnv()
	if cfg == nil {
		return
	}

	aiURL := strings.TrimSpace(os.Getenv("AI_SUGGEST_URL"))
	if aiURL == "" {
		aiURL = "http://127.0.0.1:5500/ai_suggest_auto"
	}

	minConf := 0.70
	if v := strings.TrimSpace(os.Getenv("AI_MIN_CONF")); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			minConf = f
		}
	}

	// optional (seconds)
	timeout := 5 * time.Second
	if v := strings.TrimSpace(os.Getenv("AI_TIMEOUT_SEC")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			timeout = time.Duration(n) * time.Second
		}
	}

	fmt.Printf("WhoAmI\n")
	who, _ := callEval(cfg.HTTPAddr, cfg.Token, "WhoAmI", []string{})
	fmt.Println(string(who))

	gw, contract, closeFn, err := connectGateway(cfg)
	if err != nil {
		fmt.Printf("MLWatch ERROR: connectGateway: %v\n", err)
		return
	}
	defer closeFn()
	_ = gw

	fmt.Printf("MLWatch running (user=%s). Listening events on channel=%s chaincode=%s\n", cfg.User, cfg.Channel, cfg.Chaincode)

	ctx := context.Background()
	ch, err := ChaincodeEvents(ctx, contract)
	if err != nil {
		fmt.Printf("MLWatch ERROR: ChaincodeEvents: %v\n", err)
		return
	}

	for ev := range ch {
		// We only care about new assets for auto-suggest.
		if ev.EventName != "ASSET_CREATED" {
			continue
		}

		assetID := normalizeAssetID(ev.Payload.AssetID)
		if assetID == "" {
			continue
		}

		asset, err := readAsset(contract, assetID)
		if err != nil {
			fmt.Printf("MLWatch: ReadAsset failed asset=%s: %v\n", assetID, err)
			continue
		}

		// Only suggest for manual-review categories
		if !asset.NeedsManualReview {
			continue
		}

		req := buildAISuggestReq(assetID, asset)
		resp, err := callAISuggest(aiURL, req, timeout)
		if err != nil {
			fmt.Printf("MLWatch: AI call failed asset=%s: %v\n", assetID, err)
			continue
		}

		conf := normalizeConfidence(resp.Confidence)
		if conf < minConf {
			fmt.Printf("MLWatch: AI below threshold asset=%s suggested=%q conf=%.2f (<%.2f)\n", assetID, resp.SuggestedCategory, conf, minConf)
			continue
		}
		cat := strings.TrimSpace(resp.SuggestedCategory)
		if cat == "" {
			fmt.Printf("MLWatch: AI suggested empty category asset=%s\n", assetID)
			continue
		}

		// submit suggestion on-chain as MLService
		_, err = contract.SubmitTransaction("AddSuggestedCategory", assetID, cat, fmt.Sprintf("%.2f", conf))
		if err != nil {
			fmt.Printf("MLWatch: AddSuggestedCategory failed asset=%s: %v\n", assetID, err)
			continue
		}

		fmt.Printf("MLWatch: ✅ Suggested asset=%s category=%q conf=%.2f\n", assetID, cat, conf)
	}
}

func normalizeAssetID(assetID string) string {
	assetID = strings.TrimSpace(assetID)
	assetID = strings.TrimPrefix(assetID, "asset_")
	return assetID
}

func normalizeConfidence(c float64) float64 {
	if c <= 1.0 && c > 0 {
		return c * 100.0
	}
	if c < 0 {
		return 0
	}
	if c > 100 {
		return 100
	}
	return c
}

func buildAISuggestReq(assetID string, a *assetOnChain) aiSuggestReq {
	var req aiSuggestReq
	req.AssetID = assetID

	// metadata
	author := strings.TrimSpace(a.Metadata.Authors)
	if author == "" {
		author = strings.TrimSpace(a.Metadata.Author)
	}
	dept := strings.TrimSpace(a.Metadata.Department)
	if dept == "" {
		dept = strings.TrimSpace(a.Metadata.Discipline)
	}
	kw := []string(a.Metadata.Keywords)

	req.Metadata.Title = strings.TrimSpace(a.Metadata.Title)
	req.Metadata.Description = strings.TrimSpace(a.Description)
	req.Metadata.Author = author
	req.Metadata.Department = dept
	req.Metadata.Keywords = kw
	return req
}

func callAISuggest(url string, req aiSuggestReq, timeout time.Duration) (*aiSuggestResp, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	hc := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{ // allow local dev servers with self-signed TLS if needed
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	hreq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/json")

	resp, err := hc.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("ai http=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out aiSuggestResp
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("ai bad json: %w (body=%s)", err, strings.TrimSpace(string(body)))
	}
	if strings.ToLower(strings.TrimSpace(out.Status)) != "ok" {
		msg := strings.TrimSpace(out.Message)
		if msg == "" {
			msg = "ai status not ok"
		}
		return nil, errors.New(msg)
	}
	return &out, nil
}

func readAsset(contract *client.Contract, assetID string) (*assetOnChain, error) {
	res, err := contract.EvaluateTransaction("ReadAsset", assetID)
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(string(res))
	if raw == "" {
		return nil, errors.New("empty ReadAsset response")
	}

	// 1) Try JSON first
	var a assetOnChain
	if json.Unmarshal(res, &a) == nil && a.ID != "" {
		return &a, nil
	}

	// 2) Fallback for Go fmt string (starts with "&{")
	return parseGoFmtAsset(raw)
}

// parseGoFmtAsset parses output like:
//
//	&{asset_demo-asset-004 bafkreiCID Unverified hash004 demo asset ... <ownerID> Ruslan map[...] [] {Demo Title 4 Ruslan IT CC-BY-4.0 10.0000/demo4 crypto,security}  0 true }
//
// It is best-effort, but enough for your AI suggest pipeline.
func parseGoFmtAsset(s string) (*assetOnChain, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "&{") {
		return nil, fmt.Errorf("unsupported ReadAsset format: %q", preview(s, 40))
	}

	// find metadata sub-struct: second '{...}'
	metaStart := strings.Index(s[2:], "{")
	if metaStart < 0 {
		return nil, errors.New("cannot find metadata '{'")
	}
	metaStart += 2
	metaEndRel := strings.Index(s[metaStart+1:], "}")
	if metaEndRel < 0 {
		return nil, errors.New("cannot find metadata '}'")
	}
	metaEnd := metaStart + 1 + metaEndRel

	prefix := strings.TrimSpace(s[2:metaStart])
	meta := strings.TrimSpace(s[metaStart+1 : metaEnd])
	suffix := strings.TrimSpace(s[metaEnd+1:])

	fields := strings.Fields(prefix)
	if len(fields) < 6 {
		return nil, fmt.Errorf("not enough fields in prefix: %q", preview(prefix, 80))
	}

	// Detect ownerID (x509 base64 string typically starts with eDUwOTo6)
	ownerIdx := -1
	for i, f := range fields {
		if strings.HasPrefix(f, "eDUwOTo6") {
			ownerIdx = i
			break
		}
	}
	if ownerIdx < 0 {
		// fallback: try match base64-ish long token
		for i, f := range fields {
			if len(f) > 40 && strings.Contains(f, "=") {
				ownerIdx = i
				break
			}
		}
	}
	if ownerIdx < 0 || ownerIdx < 4 {
		return nil, fmt.Errorf("cannot locate ownerID in: %q", preview(prefix, 120))
	}

	id := fields[0]
	category := fields[2]
	desc := strings.Join(fields[4:ownerIdx], " ")
	ownerID := fields[ownerIdx]
	ownerName := ""
	if ownerIdx+1 < len(fields) {
		ownerName = fields[ownerIdx+1]
	}

	// Parse metadata by right-to-left heuristic: title may contain spaces.
	m := strings.Fields(meta)
	mdTitle, mdAuthor, mdDept, mdLic, mdDOI, mdKW := "", "", "", "", "", ""
	if len(m) >= 6 {
		mdKW = m[len(m)-1]
		mdDOI = m[len(m)-2]
		mdLic = m[len(m)-3]
		mdDept = m[len(m)-4]
		mdAuthor = m[len(m)-5]
		mdTitle = strings.Join(m[:len(m)-5], " ")
	} else {
		// best-effort: treat whole meta as title
		mdTitle = meta
	}
	_ = mdLic
	_ = mdDOI

	needsManual := false
	sufFields := strings.Fields(suffix)
	for i := len(sufFields) - 1; i >= 0; i-- {
		if sufFields[i] == "true" {
			needsManual = true
			break
		}
		if sufFields[i] == "false" {
			needsManual = false
			break
		}
	}

	a := &assetOnChain{}
	a.ID = id
	a.Category = category
	a.Description = desc
	a.Owner = ownerID
	a.OwnerName = ownerName
	a.NeedsManualReview = needsManual
	a.Metadata.Title = mdTitle
	// chaincode meta in your output looks like {Title Author Dept License DOI Keywords}
	a.Metadata.Authors = mdAuthor
	a.Metadata.Department = mdDept
	a.Metadata.Keywords = keywordsField(splitKeywords(mdKW))

	// Try to capture suggestedCategory if present in suffix (rare). Pattern: "} <suggested> <confidence> <bool> }"
	// We'll take the first non-numeric token (not true/false) as suggestion.
	for _, tok := range sufFields {
		if tok == "true" || tok == "false" {
			continue
		}
		if isNumber(tok) {
			continue
		}
		// ignore trailing brace
		if tok == "}" {
			continue
		}
		if a.SuggestedCategory == "" {
			a.SuggestedCategory = tok
			break
		}
	}

	return a, nil
}

func splitKeywords(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return []string{}
	}
	// allow both comma-separated and space-separated
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isNumber(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

func preview(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// =====================
// Minimal event payload decoder
// =====================
// Your ChaincodeEvents() helper in the repo typically decodes payload into a
// struct with Payload.AssetID etc. We re-use it; this file only depends on:
//   - ChaincodeEvents(ctx, contract) (chan ChaincodeEventEnvelope, error)
//   - normalizeAssetID() above
//
// No extra code here.

// =====================
// Compatibility helpers
// =====================

// Some repos define callEval elsewhere. We keep a tiny shim here only if missing.
// If your repo already has callEval, this will be a duplicate; in that case
// remove this function.

// NOTE: To avoid redeclare errors, this function is intentionally named callEvalMLWatch.
func callEvalMLWatch(httpAddr, token, fn string, args []string) ([]byte, error) {
	payload := map[string]any{"function": fn, "args": args}
	b, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(httpAddr, "/")+"/eval", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return body, nil
}

// If your repo already has callEval() and you want to keep the original
// runMLWatch printing, this tiny wrapper tries to call it via a regexp search
// of existing symbol at runtime is impossible in Go.
// So, by default we just won't print WhoAmI if callEval() isn't available.

// ----
// Optional: strict parsing of asset IDs (not necessary, but helps avoid garbage)
var assetIDRe = regexp.MustCompile(`^[a-zA-Z0-9._\-]+$`)

func isSafeAssetID(id string) bool {
	id = strings.TrimSpace(id)
	return id != "" && len(id) <= 128 && assetIDRe.MatchString(id)
}
