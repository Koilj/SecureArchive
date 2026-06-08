package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
)

type rpcRequest struct {
	Function string   `json:"function"`
	Args     []string `json:"args"`
}

type rpcResponse struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Text   string          `json:"text,omitempty"`
	Error  string          `json:"error,omitempty"`
}
type fnPolicy struct {
	MinArgs  int
	MaxArgs  int
	MaxTotal int // max total chars across args
	MaxArg   int // max per-arg chars
}

const (
	maxRPCArgs            = 32
	maxArgLenDefault      = 10000
	maxTotalArgsLenEval   = 120000
	maxTotalArgsLenSubmit = 30000
)

var submitPolicies = map[string]fnPolicy{
	"RegisterUser":            {MinArgs: 4, MaxArgs: 4, MaxTotal: 16000, MaxArg: 6000},
	"SyncMyPublicKey":         {MinArgs: 2, MaxArgs: 2, MaxTotal: 8000, MaxArg: 6000},
	"CreateAsset":             {MinArgs: 12, MaxArgs: 12, MaxTotal: 25000, MaxArg: 10000},
	"RequestAccess":           {MinArgs: 1, MaxArgs: 1, MaxTotal: 2000, MaxArg: 2000},
	"RequestAccessWithReason": {MinArgs: 2, MaxArgs: 2, MaxTotal: 6000, MaxArg: 4000},
	"CancelMyRequest":         {MinArgs: 1, MaxArgs: 1, MaxTotal: 2000, MaxArg: 2000},

	"RequestMyEncryptedKey": {MinArgs: 1, MaxArgs: 1, MaxTotal: 2000, MaxArg: 2000},
	"GrantAccess":           {MinArgs: 3, MaxArgs: 3, MaxTotal: 12000, MaxArg: 8000},
	"RevokeAccess":          {MinArgs: 3, MaxArgs: 3, MaxTotal: 6000, MaxArg: 4000},
	"DenyAccess":            {MinArgs: 3, MaxArgs: 3, MaxTotal: 6000, MaxArg: 4000},
	"RotateAssetContent":    {MinArgs: 5, MaxArgs: 5, MaxTotal: 25000, MaxArg: 12000},
	"LogDownload":           {MinArgs: 1, MaxArgs: 1, MaxTotal: 2000, MaxArg: 2000},
	"ApproveCategory":       {MinArgs: 2, MaxArgs: 2, MaxTotal: 2000, MaxArg: 2000},
	"AddSuggestedCategory":  {MinArgs: 3, MaxArgs: 4, MaxTotal: 4000, MaxArg: 2000},

	"BlockUser":                {MinArgs: 2, MaxArgs: 2, MaxTotal: 4000, MaxArg: 3000},
	"UnblockUser":              {MinArgs: 1, MaxArgs: 1, MaxTotal: 2000, MaxArg: 2000},
	"BindServiceIdentity":      {MinArgs: 2, MaxArgs: 2, MaxTotal: 8000, MaxArg: 7000},
	"IssueEnrollmentInvite":    {MinArgs: 6, MaxArgs: 6, MaxTotal: 4000, MaxArg: 2000},
	"ReissueEnrollmentInvite":  {MinArgs: 3, MaxArgs: 3, MaxTotal: 4000, MaxArg: 2000},
	"RevokeEnrollmentInvite":   {MinArgs: 2, MaxArgs: 2, MaxTotal: 4000, MaxArg: 2000},
	"DeletePendingUser":        {MinArgs: 1, MaxArgs: 1, MaxTotal: 2000, MaxArg: 2000},
	"ActivateEnrollmentInvite": {MinArgs: 9, MaxArgs: 9, MaxTotal: 70000, MaxArg: 32000},
	"ReissueActivatedUserLocalIdentities": {
		MinArgs:  5,
		MaxArgs:  5,
		MaxTotal: 40000,
		MaxArg:   32000,
	},
	"SyncWebAuthnCredentials":   {MinArgs: 3, MaxArgs: 3, MaxTotal: 40000, MaxArg: 32000},
	"MarkRecoveryBundleCreated": {MinArgs: 3, MaxArgs: 3, MaxTotal: 512, MaxArg: 256},
}

// agentAuthDisabled returns true only when AGENT_DISABLE_AUTH is explicitly
// set to "1" or "true". Default (empty) means auth is REQUIRED.
func agentAuthDisabled() bool {
	v := strings.TrimSpace(os.Getenv("AGENT_DISABLE_AUTH"))
	return v == "1" || strings.EqualFold(v, "true")
}

func hasDisallowedChars(s string) bool {
	for _, r := range s {
		// allow common whitespace: space, \n, \r, \t
		if r == '\n' || r == '\r' || r == '\t' || r == ' ' {
			continue
		}
		// ASCII control
		if r < 0x20 || r == 0x7f {
			return true
		}
		// zero-width + bidi controls
		if (r >= 0x200B && r <= 0x200F) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2060 && r <= 0x206F) || r == 0xFEFF {
			return true
		}
	}
	return false
}

func validateRPC(req *rpcRequest, submit bool) error {
	fn := strings.TrimSpace(req.Function)
	if fn == "" {
		return fmt.Errorf("function is required")
	}
	if len(req.Args) > maxRPCArgs {
		return fmt.Errorf("too many args")
	}

	maxTotal := maxTotalArgsLenEval
	maxArg := maxArgLenDefault
	if submit {
		pol, ok := submitPolicies[fn]
		if !ok {
			return fmt.Errorf("function not allowed")
		}
		if fn == "BindServiceIdentity" {
			if os.Getenv("AGENT_USER") != "SecurityService" {
				return fmt.Errorf("BindServiceIdentity allowed only for SecurityService agent")
			}
		}

		if len(req.Args) < pol.MinArgs || len(req.Args) > pol.MaxArgs {
			return fmt.Errorf("invalid arg count")
		}
		if pol.MaxTotal > 0 {
			maxTotal = pol.MaxTotal
		} else {
			maxTotal = maxTotalArgsLenSubmit
		}
		if pol.MaxArg > 0 {
			maxArg = pol.MaxArg
		}
	} else {
		// eval: still enforce size limits & basic character sanity
		maxTotal = maxTotalArgsLenEval
		maxArg = maxArgLenDefault
	}

	total := 0
	for _, a := range req.Args {
		if len(a) > maxArg {
			return fmt.Errorf("arg too large")
		}
		total += len(a)
		if total > maxTotal {
			return fmt.Errorf("payload too large")
		}
		if hasDisallowedChars(a) {
			return fmt.Errorf("arg contains disallowed characters")
		}
	}
	return nil
}

// identitySlot holds a connected gateway and contract for one Fabric identity.
type identitySlot struct {
	role     string
	cfg      AgentConfig
	contract *client.Contract
	closeFn  func() error
}

// resolveContract picks the right contract for the given HTTP request.
// Priority: X-Agent-Role header → default (first slot).
func resolveContract(slots map[string]*identitySlot, r *http.Request) (*client.Contract, string) {
	role := strings.TrimSpace(r.Header.Get("X-Agent-Role"))
	if role != "" {
		if s, ok := slots[role]; ok {
			return s.contract, s.role
		}
	}
	// fallback to SecurityService if available, else first slot
	if s, ok := slots["SecurityService"]; ok {
		return s.contract, s.role
	}
	for _, s := range slots {
		return s.contract, s.role
	}
	return nil, ""
}

func serveHTTP() {
	addr := envOr("AGENT_HTTP_ADDR", "127.0.0.1:8090")

	cfg := defaultAgentConfig("SecurityService")

	gw, closeFn, err := connectGateway(cfg)
	if err != nil {
		log.Fatalf("CONNECT ERROR: %v", err)
	}
	defer func() { _ = closeFn() }()

	network := gw.GetNetwork(cfg.Channel)
	contract := network.GetContract(cfg.Chaincode)

	mux := http.NewServeMux()

	// Local signing service token (protects /submit and /eval from web pages)
	authDisabled := agentAuthDisabled()
	token := strings.TrimSpace(os.Getenv("AGENT_TOKEN"))
	if token == "" && !authDisabled {
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("AGENT_TOKEN unset and crypto/rand failed: %v", err)
		}
		token = base64.RawURLEncoding.EncodeToString(b)
		log.Printf("WARNING: AGENT_TOKEN not set. Generated temporary token: %s", token)
		log.Printf("Set it explicitly for stable usage: export AGENT_TOKEN=%s", token)
	}

	mux.HandleFunc("/health", withCORS(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, rpcResponse{OK: true, Text: "ok"})
	}))

	mux.HandleFunc("/eval", withCORS(requireAuth(token, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, rpcResponse{OK: false, Error: "POST only"})
			return
		}
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, rpcResponse{OK: false, Error: "bad json: " + err.Error()})
			return
		}
		if err := validateRPC(&req, false); err != nil {
			writeJSON(w, http.StatusBadRequest, rpcResponse{OK: false, Error: err.Error()})
			return
		}
		res, err := contract.EvaluateTransaction(req.Function, req.Args...)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, rpcResponse{OK: false, Error: err.Error()})
			return
		}
		writeResultBytes(w, res)
	})))

	mux.HandleFunc("/submit", withCORS(requireAuth(token, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, rpcResponse{OK: false, Error: "POST only"})
			return
		}
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, rpcResponse{OK: false, Error: "bad json: " + err.Error()})
			return
		}
		if err := validateRPC(&req, true); err != nil {
			writeJSON(w, http.StatusBadRequest, rpcResponse{OK: false, Error: err.Error()})
			return
		}
		res, err := contract.SubmitTransaction(req.Function, req.Args...)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, rpcResponse{OK: false, Error: err.Error()})
			return
		}
		writeResultBytes(w, res)
	})))

	srv := &http.Server{
		Addr:              addr,
		Handler:           logging(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// If this agent runs as SecurityService, start the risk engine in background automatically.
	if cfg.User == "SecurityService" {
		go func() {
			log.Println("RISK ENGINE: starting in background (SecurityService agent)...")
			if err := runRiskEngine(cfg); err != nil {
				log.Printf("RISK ENGINE ERROR: %v", err)
			}
		}()
	}

	log.Printf("Agent listening on http://%s (user=%s org=%s msp=%s peer=%s)\n",
		addr, cfg.User, cfg.Org, cfg.MSPID, cfg.PeerEndpoint)

	log.Fatal(srv.ListenAndServe())
}

// serveUnifiedHTTP starts a single HTTP server that multiplexes multiple Fabric
// identities (e.g. SecurityService + MLService) on one port.  Callers select
// the identity via the X-Agent-Role request header; if omitted the default
// (SecurityService) is used.
func serveUnifiedHTTP() {
	addr := envOr("AGENT_HTTP_ADDR", "127.0.0.1:8090")

	// Parse AGENT_IDENTITIES (comma-separated list of roles).
	// Default: "SecurityService,MLService"
	rolesRaw := envOr("AGENT_IDENTITIES", "SecurityService,MLService")
	var roles []string
	for _, r := range strings.Split(rolesRaw, ",") {
		r = strings.TrimSpace(r)
		if r != "" {
			roles = append(roles, r)
		}
	}
	if len(roles) == 0 {
		roles = []string{"SecurityService"}
	}

	slots := make(map[string]*identitySlot, len(roles))
	var closers []func() error

	for _, role := range roles {
		cfg := defaultAgentConfig(role)
		gw, closeFn, err := connectGateway(cfg)
		if err != nil {
			log.Printf("WARNING: could not connect identity %s: %v (skipping)", role, err)
			continue
		}
		closers = append(closers, closeFn)
		network := gw.GetNetwork(cfg.Channel)
		contract := network.GetContract(cfg.Chaincode)
		slots[role] = &identitySlot{
			role:     role,
			cfg:      cfg,
			contract: contract,
			closeFn:  closeFn,
		}
		log.Printf("UNIFIED: connected identity %s (org=%s msp=%s)", role, cfg.Org, cfg.MSPID)
	}
	defer func() {
		for _, fn := range closers {
			_ = fn()
		}
	}()

	if len(slots) == 0 {
		log.Fatal("UNIFIED: no identities connected, cannot start")
	}

	// Auth token
	authDisabled := agentAuthDisabled()
	token := strings.TrimSpace(os.Getenv("AGENT_TOKEN"))
	if token == "" && !authDisabled {
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("AGENT_TOKEN unset and crypto/rand failed: %v", err)
		}
		token = base64.RawURLEncoding.EncodeToString(b)
		log.Printf("WARNING: AGENT_TOKEN not set. Generated temporary token: %s", token)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", withCORS(func(w http.ResponseWriter, r *http.Request) {
		identities := make([]string, 0, len(slots))
		for k := range slots {
			identities = append(identities, k)
		}
		sort.Strings(identities)
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":         true,
			"text":       "ok",
			"mode":       "unified",
			"identities": identities,
		})
	}))

	mux.HandleFunc("/eval", withCORS(requireAuth(token, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, rpcResponse{OK: false, Error: "POST only"})
			return
		}
		contract, role := resolveContract(slots, r)
		if contract == nil {
			writeJSON(w, http.StatusServiceUnavailable, rpcResponse{OK: false, Error: "no identity available"})
			return
		}
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, rpcResponse{OK: false, Error: "bad json: " + err.Error()})
			return
		}
		if err := validateRPC(&req, false); err != nil {
			writeJSON(w, http.StatusBadRequest, rpcResponse{OK: false, Error: err.Error()})
			return
		}
		_ = role
		res, err := contract.EvaluateTransaction(req.Function, req.Args...)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, rpcResponse{OK: false, Error: err.Error()})
			return
		}
		writeResultBytes(w, res)
	})))

	mux.HandleFunc("/submit", withCORS(requireAuth(token, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, rpcResponse{OK: false, Error: "POST only"})
			return
		}
		contract, role := resolveContract(slots, r)
		if contract == nil {
			writeJSON(w, http.StatusServiceUnavailable, rpcResponse{OK: false, Error: "no identity available"})
			return
		}
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, rpcResponse{OK: false, Error: "bad json: " + err.Error()})
			return
		}
		if err := validateRPC(&req, true); err != nil {
			writeJSON(w, http.StatusBadRequest, rpcResponse{OK: false, Error: err.Error()})
			return
		}
		_ = role
		res, err := contract.SubmitTransaction(req.Function, req.Args...)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, rpcResponse{OK: false, Error: err.Error()})
			return
		}
		writeResultBytes(w, res)
	})))

	srv := &http.Server{
		Addr:              addr,
		Handler:           logging(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Start risk engine if SecurityService identity is present
	if secSlot, ok := slots["SecurityService"]; ok {
		go func() {
			log.Println("RISK ENGINE: starting in background (unified agent)...")
			if err := runRiskEngine(secSlot.cfg); err != nil {
				log.Printf("RISK ENGINE ERROR: %v", err)
			}
		}()
	}

	var rolesList []string
	for k := range slots {
		rolesList = append(rolesList, k)
	}
	sort.Strings(rolesList)
	log.Printf("UNIFIED agent listening on http://%s (identities=%v)\n", addr, rolesList)

	log.Fatal(srv.ListenAndServe())
}

func writeResultBytes(w http.ResponseWriter, res []byte) {
	// Если chaincode вернул JSON — отдадим как JSON, иначе как текст.
	if len(res) == 0 || (res[0] != '{' && res[0] != '[' && res[0] != '"') {
		writeJSON(w, http.StatusOK, rpcResponse{OK: true, Text: string(res)})
		return
	}
	writeJSON(w, http.StatusOK, rpcResponse{OK: true, Result: json.RawMessage(res)})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func withCORS(next http.HandlerFunc) http.HandlerFunc {
	allowed := map[string]bool{}
	// Optional: override by env ALLOWED_ORIGINS="http://localhost:8000,http://127.0.0.1:8000"
	env := strings.TrimSpace(os.Getenv("ALLOWED_ORIGINS"))
	if env != "" {
		for _, o := range strings.Split(env, ",") {
			o = strings.TrimSpace(o)
			if o != "" {
				allowed[o] = true
			}
		}
	} else {
		// Safe defaults for the local dev UI served on :8000.
		// Intentionally do NOT allow "null" (file://) or bare
		// http://localhost without a port - set ALLOWED_ORIGINS
		// explicitly to broaden this in non-dev environments.
		allowed["http://localhost:8000"] = true
		allowed["http://127.0.0.1:8000"] = true
	}

	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && !allowed[origin] {
			writeJSON(w, http.StatusForbidden, rpcResponse{OK: false, Error: "CORS origin not allowed"})
			return
		}
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func requireAuth(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if agentAuthDisabled() {
			next(w, r)
			return
		}
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, rpcResponse{OK: false, Error: "agent token not configured"})
			return
		}
		h := strings.TrimSpace(r.Header.Get("Authorization"))
		if h != "Bearer "+token {
			writeJSON(w, http.StatusUnauthorized, rpcResponse{OK: false, Error: "unauthorized"})
			return
		}
		next(w, r)
	}
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		fmt.Printf("%s %s %s\n", r.Method, r.URL.Path, time.Since(start))
	})
}
