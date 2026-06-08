package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"time"

	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const (
	// Composite-key object types for download audit indexes.
	downloadAuditByAssetIndex = "dlA"
	downloadAuditByUserIndex  = "dlU"
	auditByAssetIndex         = "auA"
	auditByUserIndex          = "auU"
	auditByTypeIndex          = "auT"
	auditByTargetUserIndex    = "auTU"
	enrollmentInvitePrefix    = "ENROLLMENT_INVITE_"
	usernameIndexPrefix       = "USER_BY_USERNAME_"
)

const (
	dataEncryptionAlgV2     = "ECDH-P256-HKDF-SHA256-AES-256-GCM"
	dataEncryptionAlgLegacy = "RSA-OAEP-2048/SHA-256"
	keyEnvelopeV2Prefix     = "SDC2:KEY:"
)

// Models

type Metadata struct {
	Title      string `json:"title"`
	Authors    string `json:"authors"`
	Discipline string `json:"discipline"`
	License    string `json:"license"`
	DOI        string `json:"doi"`
	Keywords   string `json:"keywords"`
}

type Asset struct {
	ID          string            `json:"id"`
	CIDHash     string            `json:"cidHash"`
	Category    string            `json:"category"`
	FileHash    string            `json:"fileHash"`
	Description string            `json:"description"`
	OwnerID     string            `json:"ownerID"`
	Owner       string            `json:"owner"`
	Keys        map[string]string `json:"keys"`
	AccessLog   []string          `json:"accessLog"`
	Metadata    Metadata          `json:"metadata"`

	// AI / review flow
	SuggestedCategory      string  `json:"suggestedCategory"`
	SuggestedConfidence    float64 `json:"suggestedConfidence"`
	NeedsManualReview      bool    `json:"needsManualReview"`
	ManualCategoryOverride string  `json:"manualCategoryOverride"`
}

type PublicAsset struct {
	ID          string   `json:"id"`
	CIDHash     string   `json:"cidHash"`
	Category    string   `json:"category"`
	FileHash    string   `json:"fileHash"`
	Description string   `json:"description"`
	OwnerID     string   `json:"ownerID"`
	Owner       string   `json:"owner"`
	Metadata    Metadata `json:"metadata"`

	SuggestedCategory      string  `json:"suggestedCategory"`
	SuggestedConfidence    float64 `json:"suggestedConfidence"`
	NeedsManualReview      bool    `json:"needsManualReview"`
	ManualCategoryOverride string  `json:"manualCategoryOverride"`
	AccessStatus           string  `json:"accessStatus"`
	CanDownload            bool    `json:"canDownload"`
	CanRequest             bool    `json:"canRequest"`
}

type UserProfile struct {
	UserID              string               `json:"userID"`
	Username            string               `json:"username"`
	Department          string               `json:"department"`
	Role                string               `json:"role"`
	MSPID               string               `json:"mspID"`
	PublicKey           string               `json:"publicKey"`
	Fingerprint         string               `json:"fingerprint"`
	FabricCert          string               `json:"fabricCert"`
	WebAuthnUserHandle  string               `json:"webAuthnUserHandle"`
	WebAuthnCredentials []WebAuthnCredential `json:"webAuthnCredentials"`
	CreatedAt           string               `json:"createdAt"`
	UpdatedAt           string               `json:"updatedAt"`

	WebAuthnIdentity       WebAuthnIdentity       `json:"webAuthnIdentity"`
	FabricSigningIdentity  FabricSigningIdentity  `json:"fabricSigningIdentity"`
	DataEncryptionIdentity DataEncryptionIdentity `json:"dataEncryptionIdentity"`
	RecoveryBundle         RecoveryBundleStatus   `json:"recoveryBundle"`

	IsBlocked bool `json:"isBlocked"`

	BlockedAt    string `json:"blockedAt"`
	BlockedUntil string `json:"blockedUntil"`
	BlockReason  string `json:"blockReason"`
}

type WebAuthnCredential struct {
	CredentialID      string   `json:"credentialID"`
	PublicKeyPEM      string   `json:"publicKeyPEM"`
	SignCount         uint32   `json:"signCount"`
	Transports        []string `json:"transports"`
	AAGUID            string   `json:"aaguid"`
	AttestationFormat string   `json:"attestationFormat"`
	Label             string   `json:"label"`
	RPID              string   `json:"rpID"`
	CreatedAt         string   `json:"createdAt"`
	LastUsedAt        string   `json:"lastUsedAt"`
}

type WebAuthnIdentity struct {
	UserHandle      string               `json:"userHandle"`
	Credentials     []WebAuthnCredential `json:"credentials"`
	CredentialCount int                  `json:"credentialCount"`
	LastUpdatedAt   string               `json:"lastUpdatedAt"`
}

type FabricSigningIdentity struct {
	MSPID         string `json:"mspID"`
	Certificate   string `json:"certificate"`
	Algorithm     string `json:"algorithm"`
	LastUpdatedAt string `json:"lastUpdatedAt"`
}

type DataEncryptionIdentity struct {
	PublicKey     string `json:"publicKey"`
	Fingerprint   string `json:"fingerprint"`
	Algorithm     string `json:"algorithm"`
	LastUpdatedAt string `json:"lastUpdatedAt"`
}

type RecoveryBundleStatus struct {
	Required      bool   `json:"required"`
	Created       bool   `json:"created"`
	CreatedAt     string `json:"createdAt"`
	UpdatedAt     string `json:"updatedAt"`
	BundleVersion int    `json:"bundleVersion"`
	Protection    string `json:"protection"`
}

type EnrollmentInvite struct {
	Username         string `json:"username"`
	Department       string `json:"department"`
	Role             string `json:"role"`
	Org              string `json:"org"`
	InviteID         string `json:"inviteID"`
	Status           string `json:"status"`
	IssuedAt         string `json:"issuedAt"`
	ExpiresAt        string `json:"expiresAt"`
	IssuedBy         string `json:"issuedBy"`
	UpdatedAt        string `json:"updatedAt"`
	ActivatedAt      string `json:"activatedAt"`
	UserID           string `json:"userID"`
	MSPID            string `json:"mspID"`
	ReissueCount     int    `json:"reissueCount"`
	PreviousInviteID string `json:"previousInviteID"`
	LastReissuedAt   string `json:"lastReissuedAt"`
	RevokedAt        string `json:"revokedAt"`
	RevokedBy        string `json:"revokedBy"`
	RevokedReason    string `json:"revokedReason"`
}

type AccessRequest struct {
	Department    string `json:"department"`
	AssetCategory string `json:"assetCategory"`

	AssetID     string `json:"assetID"`
	RequesterID string `json:"requesterID"`
	Requester   string `json:"requester"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
}

type ChainEvent struct {
	Type      string `json:"type"`
	AssetID   string `json:"assetID,omitempty"`
	ActorID   string `json:"actorID,omitempty"`
	TargetID  string `json:"targetID,omitempty"`
	Status    string `json:"status,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// DownloadAudit is persisted in ledger using composite keys (indexes) to allow querying
// downloads by asset or by user.
type DownloadAudit struct {
	DocType   string `json:"docType"`
	AssetID   string `json:"assetID"`
	ActorID   string `json:"actorID"`
	Timestamp string `json:"timestamp"`
	TxID      string `json:"txID"`
}

// DownloadAuditQueryResult wraps audit list for JSON serialization.
type DownloadAuditQueryResult struct {
	Items []*DownloadAudit `json:"items"`
}

// AuditEvent is a generic immutable audit record persisted in ledger.
// It is stored under multiple composite-key indexes to support querying by asset, user, and type.
type AuditEvent struct {
	DocType      string `json:"docType"`
	EventType    string `json:"eventType"`
	AssetID      string `json:"assetID"`
	ActorID      string `json:"actorID"`
	TargetUserID string `json:"targetUserID"`
	Timestamp    string `json:"timestamp"`
	TxID         string `json:"txID"`
	Detail       string `json:"detail"`
}

// AuditEventQueryResult wraps audit events list for JSON serialization.
type AuditEventQueryResult struct {
	Items []*AuditEvent `json:"items"`
}

// =====================
// Contract
// =====================

type SmartContract struct {
	contractapi.Contract
}

// =====================
// Helpers (IDs / keys / roles)
// =====================

// getAttr reads attribute from caller's X509 certificate
func getAttr(ctx contractapi.TransactionContextInterface, name string) string {
	v, ok, err := cid.GetAttributeValue(ctx.GetStub(), name)
	if err != nil || !ok {
		return ""
	}
	return v
}

func normDept(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	// убрать слова-мусор
	s = strings.ReplaceAll(s, "department", "")
	s = strings.ReplaceAll(s, "dept", "")
	s = strings.ReplaceAll(s, "center", "")
	s = strings.ReplaceAll(s, "lab", "")
	// убрать пробелы
	s = strings.ReplaceAll(s, " ", "")
	return s
}

func isManualReviewCategory(category string) bool {
	c := strings.ToLower(strings.TrimSpace(category))
	return c == "" || c == "unverified" || c == "unknown"
}

func isActionableCategory(category string) bool {
	c := strings.ToLower(strings.TrimSpace(category))
	if c == "" {
		return false
	}
	switch c {
	case "unverified", "unknown", "unclassified", "error":
		return false
	default:
		return true
	}
}

func accessFlagsFromStatus(status string) (bool, bool) {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "OWNER", "APPROVED", "GRANTED":
		return true, false
	case "PENDING":
		return false, false
	default:
		return false, true
	}
}

func (s *SmartContract) assetAccessStatusForViewer(ctx contractapi.TransactionContextInterface, asset *Asset, viewerID string) string {
	if asset == nil || strings.TrimSpace(viewerID) == "" {
		return "NONE"
	}
	if asset.OwnerID == viewerID {
		return "OWNER"
	}
	if asset.Keys != nil {
		if resolvedKey, ok := resolveUserKeyInMap(asset.Keys, viewerID); ok {
			if strings.TrimSpace(asset.Keys[resolvedKey]) != "" {
				return "APPROVED"
			}
		}
	}
	reqK, _ := reqKey(ctx, asset.ID, viewerID)
	reqBytes, err := ctx.GetStub().GetState(reqK)
	if err != nil || len(reqBytes) == 0 {
		return "NONE"
	}
	var req AccessRequest
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return "NONE"
	}
	status := strings.ToUpper(strings.TrimSpace(req.Status))
	if status == "" {
		return "NONE"
	}
	// A stale APPROVED request without a current encrypted key must not be
	// presented as downloadable access. Treat it as no current access so the
	// UI can offer a fresh request/reopen action.
	if status == "APPROVED" {
		return "NONE"
	}
	return status
}

// policyAllowsDepartment implements a minimal ABAC policy:
// department -> allowed scientific categories.
// NOTE: for empty/unverified/unknown categories we do NOT auto-deny (manual review by owner).
func policyAllowsDepartment(dept string, category string) bool {
	if isManualReviewCategory(category) {
		return true
	}

	catLower := strings.ToLower(strings.TrimSpace(category))
	deptNorm := normDept(dept)

	// Hard-deny buckets (ABAC strict categories). Unknown categories are generally manual-review,
	// but these are explicit "restricted" categories.
	if catLower == "confidential" || catLower == "restricted" {
		// Only IT department is allowed by default.
		return deptNorm == "it"
	}

	itCats := map[string]bool{
		"it document":               true,
		"cryptography and security": true,
		"artificial intelligence":   true,
		"databases":                 true,
		"software engineering":      true,
		"it":                        true,
		"information technology":    true,
	}
	physCats := map[string]bool{
		"quantum physics":       true,
		"computational physics": true,
		"particle physics":      true,
		"physics":               true,
		"astrophysics":          true,
	}
	bioCats := map[string]bool{
		"biology":        true,
		"genetics":       true,
		"neuroscience":   true,
		"bioinformatics": true,
		"medicine":       true,
		"medical":        true,
	}

	switch {
	case itCats[catLower]:
		return deptNorm == "it"
	case physCats[catLower]:
		return deptNorm == "physics"
	case bioCats[catLower]:
		return deptNorm == "biology" || deptNorm == "medical"
	default:
		// unknown category -> don't auto-deny
		return true
	}
}

func serviceBindingKey(service string) string {
	return "SERVICE_BINDING_" + service
}

func enrollmentInviteKey(username string) string {
	return enrollmentInvitePrefix + strings.ToLower(strings.TrimSpace(username))
}

func normalizeInviteStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "active", "pending":
		return "pending"
	case "activated":
		return "activated"
	case "revoked":
		return "revoked"
	default:
		return strings.ToLower(strings.TrimSpace(status))
	}
}

func isPendingInviteStatus(status string) bool {
	return normalizeInviteStatus(status) == "pending"
}

func userByUsernameKey(username string) string {
	return usernameIndexPrefix + strings.ToLower(strings.TrimSpace(username))
}

const assetPrefix1 = "asset_"
const assetPrefix2 = "asset"

// =====================
// DISP-like on-chain validators (defense-in-depth)
// =====================
//
// IMPORTANT: We *reject* suspicious inputs instead of silently mutating them,
// because ledger data is immutable and may be rendered in UIs later.

const (
	maxAssetIDLen      = 128
	maxCIDLen          = 128
	maxCategoryLen     = 64
	maxFileHashLen     = 64 // sha256 hex
	maxEncryptedKeyLen = 4096

	maxTitleLen       = 256
	maxAuthorsLen     = 256
	maxDisciplineLen  = 128
	maxLicenseLen     = 128
	maxDOILen         = 128
	maxKeywordsLen    = 512
	maxDescriptionLen = 2000

	maxUsernameLen    = 256
	maxPublicKeyLen   = 6000
	maxFingerprintLen = 512
	maxFabricCertLen  = 12000
	maxInviteIDLen    = 256
	maxUserHandleLen  = 512
	maxRPIDLen        = 256
	maxLabelLen       = 128
	maxAAGUIDLen      = 128
	maxCredentialsLen = 32000
	maxReasonLen      = 512
)

var (
	reHex64    = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	reCID      = regexp.MustCompile(`^[A-Za-z0-9]+$`)
	reCategory = regexp.MustCompile(`^[A-Za-z0-9 _\-\.]{1,64}$`)
	reAssetID  = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,128}$`)
)

// containsDisallowedRunes blocks control chars (except \n, \r, \t) and
// unicode zero-width / bidi controls which are frequently abused for spoofing.
func containsDisallowedRunes(s string) bool {
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' || r == ' ' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return true
		}
		if (r >= 0x200B && r <= 0x200F) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2060 && r <= 0x206F) || r == 0xFEFF {
			return true
		}
	}
	return false
}

func validateTextField(name string, s string, maxLen int, allowEmpty bool) error {
	s = strings.TrimSpace(s)
	if !allowEmpty && s == "" {
		return fmt.Errorf("%s must not be empty", name)
	}
	if len(s) > maxLen {
		return fmt.Errorf("%s too long", name)
	}
	if containsDisallowedRunes(s) {
		return fmt.Errorf("%s contains disallowed characters", name)
	}
	return nil
}

func validateAssetIDValue(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("asset id must not be empty")
	}
	if len(id) > maxAssetIDLen {
		return fmt.Errorf("asset id too long")
	}
	if containsDisallowedRunes(id) {
		return fmt.Errorf("asset id contains disallowed characters")
	}
	// Accept both "asset_" and "assetXYZ" prefixes from existing code, but enforce allowed charset.
	if !reAssetID.MatchString(id) {
		return fmt.Errorf("asset id has invalid format")
	}
	return nil
}

func validateCID(cidStr string) error {
	cidStr = strings.TrimSpace(cidStr)
	if cidStr == "" {
		return fmt.Errorf("cidHash must not be empty")
	}
	if len(cidStr) > maxCIDLen {
		return fmt.Errorf("cidHash too long")
	}
	if containsDisallowedRunes(cidStr) {
		return fmt.Errorf("cidHash contains disallowed characters")
	}
	if !reCID.MatchString(cidStr) {
		return fmt.Errorf("cidHash has invalid format")
	}
	return nil
}

func validateFileHash(h string) error {
	h = strings.TrimSpace(h)
	if !reHex64.MatchString(h) {
		return fmt.Errorf("fileHash must be 64 hex chars (sha256)")
	}
	return nil
}

func validateCategory(cat string) error {
	cat = strings.TrimSpace(cat)
	if cat == "" {
		return fmt.Errorf("category must not be empty")
	}
	if len(cat) > maxCategoryLen {
		return fmt.Errorf("category too long")
	}
	if containsDisallowedRunes(cat) {
		return fmt.Errorf("category contains disallowed characters")
	}
	if !reCategory.MatchString(cat) {
		return fmt.Errorf("category has invalid format")
	}
	return nil
}

func validateEncryptedKey(k string) error {
	k = strings.TrimSpace(k)
	if k == "" {
		return fmt.Errorf("encrypted key must not be empty")
	}
	if len(k) > maxEncryptedKeyLen {
		return fmt.Errorf("encrypted key too long")
	}
	if containsDisallowedRunes(k) {
		return fmt.Errorf("encrypted key contains disallowed characters")
	}
	if strings.HasPrefix(k, keyEnvelopeV2Prefix) {
		var env struct {
			Type          string                 `json:"type"`
			Version       int                    `json:"version"`
			Alg           string                 `json:"alg"`
			Epk           map[string]interface{} `json:"epk"`
			SaltB64       string                 `json:"saltB64"`
			IvB64         string                 `json:"ivB64"`
			CiphertextB64 string                 `json:"ciphertextB64"`
		}
		raw := strings.TrimPrefix(k, keyEnvelopeV2Prefix)
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return fmt.Errorf("key envelope v2 is not valid base64")
		}
		if len(decoded) > maxEncryptedKeyLen {
			return fmt.Errorf("key envelope v2 payload too large")
		}
		if err := json.Unmarshal(decoded, &env); err != nil {
			return fmt.Errorf("key envelope v2 is not valid JSON")
		}
		if env.Type != "securedata.key-envelope" || env.Version != 2 || env.Alg != dataEncryptionAlgV2 {
			return fmt.Errorf("key envelope v2 has unsupported type/version/algorithm")
		}
		if len(env.Epk) == 0 || strings.TrimSpace(env.SaltB64) == "" || strings.TrimSpace(env.IvB64) == "" || strings.TrimSpace(env.CiphertextB64) == "" {
			return fmt.Errorf("key envelope v2 missing required fields")
		}
		for _, item := range []string{env.SaltB64, env.IvB64, env.CiphertextB64} {
			if _, err := base64.StdEncoding.DecodeString(item); err != nil {
				return fmt.Errorf("key envelope v2 contains invalid base64 fields")
			}
		}
	}
	return nil
}

func dataEncryptionAlgorithmForPublicKey(publicKey string) string {
	pk := strings.TrimSpace(publicKey)
	if strings.HasPrefix(pk, "SECUREDATA-ECDH-P256-HKDF-SHA256") {
		return dataEncryptionAlgV2
	}
	return dataEncryptionAlgLegacy
}

func normalizeAssetID(id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", fmt.Errorf("asset id must not be empty")
	}

	// accept both "asset_" and "assetXYZ"
	if strings.HasPrefix(id, assetPrefix1) || strings.HasPrefix(id, assetPrefix2) {
		if err := validateAssetIDValue(id); err != nil {
			return "", err
		}
		return id, nil
	}

	// if UI sends "PHY123" -> becomes "asset_PHY123"
	id2 := assetPrefix1 + id
	if err := validateAssetIDValue(id2); err != nil {
		return "", err
	}
	return id2, nil
}

func isAssetKey(k string) bool {
	return strings.HasPrefix(k, assetPrefix1) || strings.HasPrefix(k, assetPrefix2)
}

func userKey(userID string) string {
	return "USER_" + userID
}

func (s *SmartContract) putUserProfile(ctx contractapi.TransactionContextInterface, u *UserProfile) error {
	if u == nil {
		return fmt.Errorf("user profile is nil")
	}
	if u.DataEncryptionIdentity.PublicKey == "" && u.PublicKey != "" {
		u.DataEncryptionIdentity.PublicKey = u.PublicKey
	}
	if u.DataEncryptionIdentity.Fingerprint == "" && u.Fingerprint != "" {
		u.DataEncryptionIdentity.Fingerprint = u.Fingerprint
	}
	if u.DataEncryptionIdentity.Algorithm == "" && u.DataEncryptionIdentity.PublicKey != "" {
		u.DataEncryptionIdentity.Algorithm = dataEncryptionAlgorithmForPublicKey(u.DataEncryptionIdentity.PublicKey)
	}
	if u.PublicKey == "" && u.DataEncryptionIdentity.PublicKey != "" {
		u.PublicKey = u.DataEncryptionIdentity.PublicKey
	}
	if u.Fingerprint == "" && u.DataEncryptionIdentity.Fingerprint != "" {
		u.Fingerprint = u.DataEncryptionIdentity.Fingerprint
	}

	if u.FabricSigningIdentity.MSPID == "" && u.MSPID != "" {
		u.FabricSigningIdentity.MSPID = u.MSPID
	}
	if u.FabricSigningIdentity.Certificate == "" && u.FabricCert != "" {
		u.FabricSigningIdentity.Certificate = u.FabricCert
	}
	if u.FabricSigningIdentity.Algorithm == "" && u.FabricSigningIdentity.Certificate != "" {
		u.FabricSigningIdentity.Algorithm = "ECDSA-P256"
	}
	if u.MSPID == "" && u.FabricSigningIdentity.MSPID != "" {
		u.MSPID = u.FabricSigningIdentity.MSPID
	}
	if u.FabricCert == "" && u.FabricSigningIdentity.Certificate != "" {
		u.FabricCert = u.FabricSigningIdentity.Certificate
	}

	if u.WebAuthnIdentity.UserHandle == "" && u.WebAuthnUserHandle != "" {
		u.WebAuthnIdentity.UserHandle = u.WebAuthnUserHandle
	}
	if len(u.WebAuthnIdentity.Credentials) == 0 && len(u.WebAuthnCredentials) > 0 {
		u.WebAuthnIdentity.Credentials = u.WebAuthnCredentials
	}
	if u.WebAuthnUserHandle == "" && u.WebAuthnIdentity.UserHandle != "" {
		u.WebAuthnUserHandle = u.WebAuthnIdentity.UserHandle
	}
	if len(u.WebAuthnCredentials) == 0 && len(u.WebAuthnIdentity.Credentials) > 0 {
		u.WebAuthnCredentials = u.WebAuthnIdentity.Credentials
	}
	u.WebAuthnIdentity.CredentialCount = len(u.WebAuthnIdentity.Credentials)

	b, err := json.Marshal(u)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(userKey(u.UserID), b); err != nil {
		return err
	}
	if strings.TrimSpace(u.Username) != "" {
		if err := ctx.GetStub().PutState(userByUsernameKey(u.Username), []byte(strings.TrimSpace(u.UserID))); err != nil {
			return err
		}
	}
	return nil
}

func (s *SmartContract) getUserIDByUsername(ctx contractapi.TransactionContextInterface, username string) (string, error) {
	b, err := ctx.GetStub().GetState(userByUsernameKey(username))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (s *SmartContract) getUserProfileByUsername(ctx contractapi.TransactionContextInterface, username string) (*UserProfile, error) {
	userID, err := s.getUserIDByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if userID == "" {
		return nil, nil
	}
	return s.getUserProfile(ctx, userID)
}

func (s *SmartContract) getEnrollmentInvite(ctx contractapi.TransactionContextInterface, username string) (*EnrollmentInvite, error) {
	b, err := ctx.GetStub().GetState(enrollmentInviteKey(username))
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, nil
	}
	var invite EnrollmentInvite
	if err := json.Unmarshal(b, &invite); err != nil {
		return nil, err
	}
	invite.Status = normalizeInviteStatus(invite.Status)
	return &invite, nil
}

func (s *SmartContract) putEnrollmentInvite(ctx contractapi.TransactionContextInterface, invite *EnrollmentInvite) error {
	if invite == nil {
		return fmt.Errorf("enrollment invite is nil")
	}
	invite.Status = normalizeInviteStatus(invite.Status)
	b, err := json.Marshal(invite)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(enrollmentInviteKey(invite.Username), b)
}

func reqKey(ctx contractapi.TransactionContextInterface, assetID, requesterID string) (string, error) {
	return "REQ_" + assetID + "_" + requesterID, nil
}

// resolveRequestForAsset tries to load an access request for (assetID, requesterInput).
// requesterInput can be a canonical requesterID, a base64/x509 string, or a human alias.
// It returns (canonicalRequesterID, requestKey, requestBytes). If not found, requestBytes is nil.
func resolveRequestForAsset(ctx contractapi.TransactionContextInterface, assetID, ownerID, requesterInput string) (string, string, []byte, error) {
	// 1) Direct lookup by provided requesterInput (may already be canonical requesterID)
	rk, _ := reqKey(ctx, assetID, requesterInput)
	b, err := ctx.GetStub().GetState(rk)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to read request: %v", err)
	}
	if b != nil {
		return requesterInput, rk, b, nil
	}

	// 2) Scan request keys: REQ_<assetID>_<requesterID>
	candidates := make(map[string]string)

	reqPrefix := "REQ_" + assetID + "_"
	it, itErr := ctx.GetStub().GetStateByRange(reqPrefix, reqPrefix+string(rune(0x10FFFF)))
	if itErr != nil {
		return "", "", nil, fmt.Errorf("failed to scan requests: %v", itErr)
	}
	for it.HasNext() {
		kv, e := it.Next()
		if e != nil {
			_ = it.Close()
			return "", "", nil, fmt.Errorf("failed to iterate requests: %v", e)
		}
		if strings.HasPrefix(kv.Key, reqPrefix) {
			rid := strings.TrimSpace(kv.Key[len(reqPrefix):])
			if rid != "" {
				candidates[rid] = ""
			}
		}
	}
	_ = it.Close()

	// 3) Fallback: scan owner-index keys (REQO_<ownerID>_<assetID>_<requesterID>)
	if len(candidates) == 0 {
		ownerRaw := ownerID
		ownerB64 := base64.StdEncoding.EncodeToString([]byte(ownerRaw))
		prefixes := []string{
			"REQO_" + ownerRaw + "_" + assetID + "_",
			"REQO_" + ownerB64 + "_" + assetID + "_",
		}
		for _, pfx := range prefixes {
			it2, itErr2 := ctx.GetStub().GetStateByRange(pfx, pfx+string(rune(0x10FFFF)))
			if itErr2 != nil {
				continue
			}
			for it2.HasNext() {
				kv, e := it2.Next()
				if e != nil {
					_ = it2.Close()
					break
				}
				rid := strings.TrimSpace(kv.Key[len(pfx):])
				if rid != "" {
					candidates[rid] = ""
				}
			}
			_ = it2.Close()
		}
	}

	if resolved, ok := resolveUserKeyInMap(candidates, requesterInput); ok {
		rk2, _ := reqKey(ctx, assetID, resolved)
		b2, err2 := ctx.GetStub().GetState(rk2)
		if err2 != nil {
			return "", "", nil, fmt.Errorf("failed to read request: %v", err2)
		}
		if b2 != nil {
			return resolved, rk2, b2, nil
		}
	}

	return "", "", nil, nil
}

// индекс заявок владельца: REQO_<ownerID>_<assetID>_<requesterID>
func reqOwnerIndexKey(ctx contractapi.TransactionContextInterface, ownerID, assetID, requesterID string) (string, error) {
	return "REQO_" + ownerID + "_" + assetID + "_" + requesterID, nil
}

// =====================
// Identity helpers (robust matching)
// =====================

// extractCN tries to extract the Common Name (CN=...) from an x509::... client id string.
func extractCN(s string) string {
	s = strings.TrimSpace(s)
	idx := strings.Index(s, "CN=")
	if idx < 0 {
		return ""
	}
	s = s[idx+3:]
	end := strings.IndexAny(s, ",:/")
	if end < 0 {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(s[:end])
}

// resolveUserKeyInMap tries to resolve an input identifier to an actual key present in a map.
// Supports: exact match, trimmed match, base64(decoded) match, base64(encoded) match, and CN=username match.
func resolveUserKeyInMap(m map[string]string, input string) (string, bool) {
	if m == nil {
		return "", false
	}
	in := strings.TrimSpace(input)
	if in == "" {
		return "", false
	}

	// 1) exact (already canonical)
	if _, ok := m[in]; ok {
		return in, true
	}

	// 2) try base64 decode input -> decoded id
	if b, err := base64.StdEncoding.DecodeString(in); err == nil {
		dec := strings.TrimSpace(string(b))
		if dec != "" {
			if _, ok := m[dec]; ok {
				return dec, true
			}
			enc := base64.StdEncoding.EncodeToString([]byte(dec))
			if _, ok := m[enc]; ok {
				return enc, true
			}
		}
	}

	// 3) try base64-encoding input (if ledger stores base64(x509::...))
	enc := base64.StdEncoding.EncodeToString([]byte(in))
	if _, ok := m[enc]; ok {
		return enc, true
	}

	// 4) try match by CN=username (best-effort)
	for k := range m {
		cand := k
		if b, err := base64.StdEncoding.DecodeString(k); err == nil {
			cand = string(b)
		}
		cn := extractCN(cand)
		if cn != "" && strings.EqualFold(cn, in) {
			return k, true
		}
	}
	return "", false
}

// =====================
// Time / events
// =====================

func txTimeRFC3339(ctx contractapi.TransactionContextInterface) (string, error) {
	ts, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return "", err
	}
	// RFC3339 without nanos
	return time.Unix(ts.Seconds, 0).UTC().Format(time.RFC3339), nil
}

func emitEvent(ctx contractapi.TransactionContextInterface, name string, ev ChainEvent) {
	b, _ := json.Marshal(ev)
	_ = ctx.GetStub().SetEvent(name, b)
}

func requireRole(ctx contractapi.TransactionContextInterface, role string) error {
	val, found, err := cid.GetAttributeValue(ctx.GetStub(), "role")
	if err != nil {
		return fmt.Errorf("failed to read role attribute: %v", err)
	}
	if !found || val != role {
		return fmt.Errorf("access denied: requires role=%s", role)
	}
	return nil
}

// requireAnyRole checks that caller has one of allowed roles.
func requireAnyRole(ctx contractapi.TransactionContextInterface, roles ...string) error {
	val, found, err := cid.GetAttributeValue(ctx.GetStub(), "role")
	if err != nil {
		return fmt.Errorf("failed to read role attribute: %v", err)
	}
	if !found {
		return fmt.Errorf("access denied: role attribute missing")
	}
	for _, r := range roles {
		if val == r {
			return nil
		}
	}
	return fmt.Errorf("access denied: requires role in [%s]", strings.Join(roles, ","))
}

func txTime(ctx contractapi.TransactionContextInterface) (time.Time, error) {
	ts, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(ts.Seconds, int64(ts.Nanos)).UTC(), nil
}

func parseRFC3339(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, strings.TrimSpace(s))
}

// isBlockedAt: возвращает (blockedNow, expired)
func isBlockedAt(u *UserProfile, now time.Time) (bool, bool) {
	if u == nil {
		return false, false
	}
	untilRaw := strings.TrimSpace(u.BlockedUntil)

	// нет until => либо не заблокирован, либо “перманентно”
	if untilRaw == "" {
		if u.IsBlocked {
			return true, false // перманентно
		}
		return false, false
	}

	until, err := parseRFC3339(untilRaw)
	if err != nil {
		// если until битый — безопаснее считать заблокированным
		return true, false
	}

	if now.Before(until) {
		return true, false
	}
	return false, true // истекло
}

// =====================
// User profile
// =====================

func (s *SmartContract) getUserProfile(ctx contractapi.TransactionContextInterface, userID string) (*UserProfile, error) {
	b, err := ctx.GetStub().GetState(userKey(userID))
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, nil
	}
	var u UserProfile
	if err := json.Unmarshal(b, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *SmartContract) requireUserProfile(ctx contractapi.TransactionContextInterface, userID string) (*UserProfile, error) {
	u, err := s.getUserProfile(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, fmt.Errorf("user %s is not registered; call RegisterUser first", userID)
	}
	return u, nil
}

func (s *SmartContract) checkBlocked(ctx contractapi.TransactionContextInterface, userID string) (bool, string, string, error) {
	u, err := s.getUserProfile(ctx, userID)
	if err != nil {
		return false, "", "", err
	}
	if u == nil {
		return false, "", "", nil
	}

	now, err := txTime(ctx)
	if err != nil {
		return false, "", "", err
	}

	blockedNow, expired := isBlockedAt(u, now)

	// IMPORTANT:
	// We do NOT mutate ledger state here (no auto-unblock), because tx timestamp/time skew between
	// clients can lead to premature unblock. Cleanup should be an explicit SecurityService action.
	if expired {
		return false, u.BlockReason, u.BlockedUntil, nil
	}
	if blockedNow {
		return true, u.BlockReason, u.BlockedUntil, nil
	}
	return false, "", "", nil
}

func (s *SmartContract) RegisterUser(ctx contractapi.TransactionContextInterface, username, publicKey, departmentIgnored, fingerprint string) error {
	userID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return fmt.Errorf("failed to get client ID: %v", err)
	}
	mspID, _ := cid.GetMSPID(ctx.GetStub())

	// Берём атрибуты ТОЛЬКО из сертификата
	dept, _, err := cid.GetAttributeValue(ctx.GetStub(), "department")
	if err != nil {
		dept = ""
	}
	role, _, err := cid.GetAttributeValue(ctx.GetStub(), "role")
	if err != nil {
		role = ""
	}

	username = strings.TrimSpace(username)
	publicKey = strings.TrimSpace(publicKey)
	fingerprint = strings.TrimSpace(fingerprint)
	existing, err := s.getUserProfile(ctx, userID)
	if err != nil {
		return err
	}

	if err := validateTextField("username", username, maxUsernameLen, false); err != nil {
		return err
	}
	if err := validateTextField("publicKey", publicKey, maxPublicKeyLen, true); err != nil {
		return err
	}
	if err := validateTextField("fingerprint", fingerprint, maxFingerprintLen, true); err != nil {
		return err
	}

	now, _ := txTimeRFC3339(ctx)
	u := UserProfile{
		UserID:      userID,
		Username:    username,
		Department:  dept,
		Role:        role,
		MSPID:       mspID,
		PublicKey:   publicKey,
		Fingerprint: fingerprint,
		CreatedAt:   now,
		UpdatedAt:   now,
		DataEncryptionIdentity: DataEncryptionIdentity{
			PublicKey:     publicKey,
			Fingerprint:   fingerprint,
			Algorithm:     dataEncryptionAlgorithmForPublicKey(publicKey),
			LastUpdatedAt: now,
		},
		FabricSigningIdentity: FabricSigningIdentity{
			MSPID:         mspID,
			Algorithm:     "ECDSA-P256",
			LastUpdatedAt: now,
		},
		WebAuthnIdentity: WebAuthnIdentity{
			LastUpdatedAt: now,
		},
		IsBlocked: false,
	}
	if existing != nil {
		u.IsBlocked = existing.IsBlocked
		u.BlockedAt = existing.BlockedAt
		u.BlockedUntil = existing.BlockedUntil
		u.BlockReason = existing.BlockReason
		u.FabricCert = existing.FabricCert
		u.WebAuthnUserHandle = existing.WebAuthnUserHandle
		u.WebAuthnCredentials = existing.WebAuthnCredentials
		u.CreatedAt = existing.CreatedAt
		u.RecoveryBundle = existing.RecoveryBundle
		u.WebAuthnIdentity = existing.WebAuthnIdentity
		u.FabricSigningIdentity = existing.FabricSigningIdentity
		u.DataEncryptionIdentity = existing.DataEncryptionIdentity
		if strings.TrimSpace(u.PublicKey) == "" {
			u.PublicKey = existing.PublicKey
		}
		if strings.TrimSpace(u.Fingerprint) == "" {
			u.Fingerprint = existing.Fingerprint
		}
		if u.CreatedAt == "" {
			u.CreatedAt = now
		}
	}
	u.UpdatedAt = now
	u.DataEncryptionIdentity.PublicKey = u.PublicKey
	u.DataEncryptionIdentity.Fingerprint = u.Fingerprint
	u.DataEncryptionIdentity.Algorithm = dataEncryptionAlgorithmForPublicKey(u.PublicKey)
	u.DataEncryptionIdentity.LastUpdatedAt = now
	u.FabricSigningIdentity.MSPID = mspID
	if u.FabricSigningIdentity.Algorithm == "" {
		u.FabricSigningIdentity.Algorithm = "ECDSA-P256"
	}
	u.FabricSigningIdentity.LastUpdatedAt = now

	if err := s.putUserProfile(ctx, &u); err != nil {
		return err
	}

	emitEvent(ctx, "USER_REGISTERED", ChainEvent{
		Type:      "USER_REGISTERED",
		ActorID:   userID,
		Timestamp: now,
	})
	return nil
}

func (s *SmartContract) SyncMyPublicKey(ctx contractapi.TransactionContextInterface, publicKey string, fingerprint string) error {
	userID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return fmt.Errorf("failed to get client ID: %v", err)
	}

	publicKey = strings.TrimSpace(publicKey)
	fingerprint = strings.TrimSpace(fingerprint)
	if err := validateTextField("publicKey", publicKey, maxPublicKeyLen, false); err != nil {
		return err
	}
	if err := validateTextField("fingerprint", fingerprint, maxFingerprintLen, true); err != nil {
		return err
	}

	u, err := s.requireUserProfile(ctx, userID)
	if err != nil {
		return err
	}

	now, _ := txTimeRFC3339(ctx)
	u.PublicKey = publicKey
	u.Fingerprint = fingerprint
	u.UpdatedAt = now
	u.DataEncryptionIdentity.PublicKey = publicKey
	u.DataEncryptionIdentity.Fingerprint = fingerprint
	u.DataEncryptionIdentity.Algorithm = dataEncryptionAlgorithmForPublicKey(publicKey)
	u.DataEncryptionIdentity.LastUpdatedAt = now

	if err := s.putUserProfile(ctx, u); err != nil {
		return err
	}

	emitEvent(ctx, "USER_PUBLIC_KEY_SYNCED", ChainEvent{
		Type:      "USER_PUBLIC_KEY_SYNCED",
		ActorID:   userID,
		Timestamp: now,
	})
	_ = s.writeAuditEvent(ctx, "USER_PUBLIC_KEY_SYNCED", "", userID, "", "public key updated")
	return nil
}

func (s *SmartContract) ReissueActivatedUserLocalIdentities(
	ctx contractapi.TransactionContextInterface,
	userID string,
	username string,
	publicKey string,
	fingerprint string,
	fabricCert string,
) error {
	if err := requireRole(ctx, "SecurityService"); err != nil {
		return err
	}

	userID = strings.TrimSpace(userID)
	username = strings.TrimSpace(username)
	publicKey = strings.TrimSpace(publicKey)
	fingerprint = strings.TrimSpace(fingerprint)
	fabricCert = strings.TrimSpace(fabricCert)

	if err := validateTextField("userID", userID, maxFabricCertLen, false); err != nil {
		return err
	}
	if err := validateTextField("username", username, maxUsernameLen, false); err != nil {
		return err
	}
	if err := validateTextField("publicKey", publicKey, maxPublicKeyLen, false); err != nil {
		return err
	}
	if err := validateTextField("fingerprint", fingerprint, maxFingerprintLen, true); err != nil {
		return err
	}
	if err := validateTextField("fabricCert", fabricCert, maxFabricCertLen, false); err != nil {
		return err
	}

	u, err := s.requireUserProfile(ctx, userID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(u.Username) != username {
		return fmt.Errorf("username does not match user profile")
	}
	if existingByName, err := s.getUserProfileByUsername(ctx, username); err != nil {
		return err
	} else if existingByName == nil || existingByName.UserID != userID {
		return fmt.Errorf("username already mapped to another userID")
	}

	now, _ := txTimeRFC3339(ctx)
	u.PublicKey = publicKey
	u.Fingerprint = fingerprint
	u.FabricCert = fabricCert
	u.UpdatedAt = now

	u.DataEncryptionIdentity.PublicKey = publicKey
	u.DataEncryptionIdentity.Fingerprint = fingerprint
	u.DataEncryptionIdentity.Algorithm = dataEncryptionAlgorithmForPublicKey(publicKey)
	u.DataEncryptionIdentity.LastUpdatedAt = now

	u.FabricSigningIdentity.MSPID = u.MSPID
	u.FabricSigningIdentity.Certificate = fabricCert
	if u.FabricSigningIdentity.Algorithm == "" {
		u.FabricSigningIdentity.Algorithm = "ECDSA-P256"
	}
	u.FabricSigningIdentity.LastUpdatedAt = now

	u.RecoveryBundle.Required = true
	u.RecoveryBundle.Created = false
	u.RecoveryBundle.CreatedAt = ""
	u.RecoveryBundle.UpdatedAt = now
	if u.RecoveryBundle.BundleVersion <= 0 {
		u.RecoveryBundle.BundleVersion = 1
	}
	if strings.TrimSpace(u.RecoveryBundle.Protection) == "" {
		u.RecoveryBundle.Protection = "Argon2id+Aes256Gcm"
	}

	if err := s.putUserProfile(ctx, u); err != nil {
		return err
	}

	actor, _ := cid.GetID(ctx.GetStub())
	emitEvent(ctx, "USER_LOCAL_IDENTITIES_REISSUED", ChainEvent{
		Type:      "USER_LOCAL_IDENTITIES_REISSUED",
		ActorID:   actor,
		TargetID:  userID,
		Timestamp: now,
	})
	_ = s.writeAuditEvent(ctx, "USER_LOCAL_IDENTITIES_REISSUED", "", actor, userID, fmt.Sprintf("username=%s", username))
	return nil
}

const defaultBlockSeconds = 120 // 2 минуты для теста (потом поставишь 600/900 и т.д.)

func (s *SmartContract) BlockUser(ctx contractapi.TransactionContextInterface, targetUserID string, reason string) error {
	return s.BlockUserForSeconds(ctx, targetUserID, fmt.Sprintf("%d", defaultBlockSeconds), reason)
}

func (s *SmartContract) UnblockUser(ctx contractapi.TransactionContextInterface, targetUserID string) error {
	if err := requireRole(ctx, "SecurityService"); err != nil {
		return err
	}

	u, err := s.getUserProfile(ctx, targetUserID)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("user not found")
	}

	u.IsBlocked = false
	u.BlockedAt = ""
	u.BlockedUntil = ""
	u.BlockReason = ""

	b, _ := json.Marshal(u)
	if err := ctx.GetStub().PutState(userKey(targetUserID), b); err != nil {
		return err
	}

	actor, _ := cid.GetID(ctx.GetStub())
	// Ledger audit: USER_UNBLOCKED
	_ = s.writeAuditEvent(ctx, "USER_UNBLOCKED", "", actor, targetUserID, "")
	t, _ := txTimeRFC3339(ctx)
	emitEvent(ctx, "USER_UNBLOCKED", ChainEvent{
		Type:      "USER_UNBLOCKED",
		TargetID:  targetUserID,
		ActorID:   actor,
		Timestamp: t,
	})

	return nil
}

func (s *SmartContract) BlockUserForSeconds(ctx contractapi.TransactionContextInterface, targetUserID string, secondsStr string, reason string) error {
	if err := requireAnyRole(ctx, "SecurityService", "RiskService"); err != nil {
		return err
	}

	reason = strings.TrimSpace(reason)
	if err := validateTextField("reason", reason, maxReasonLen, true); err != nil {
		return err
	}

	u, err := s.getUserProfile(ctx, targetUserID)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("user not found")
	}

	secs, err := strconv.Atoi(strings.TrimSpace(secondsStr))
	if err != nil || secs <= 0 {
		return fmt.Errorf("seconds must be positive integer")
	}

	now, err := txTime(ctx)
	if err != nil {
		return err
	}

	until := now.Add(time.Duration(secs) * time.Second)

	u.IsBlocked = true
	u.BlockedAt = now.Format(time.RFC3339)
	u.BlockedUntil = until.Format(time.RFC3339)
	u.BlockReason = strings.TrimSpace(reason)

	b, _ := json.Marshal(u)
	if err := ctx.GetStub().PutState(userKey(targetUserID), b); err != nil {
		return err
	}

	actor, _ := cid.GetID(ctx.GetStub())
	// Ledger audit: USER_BLOCKED
	_ = s.writeAuditEvent(ctx, "USER_BLOCKED", "", actor, targetUserID, fmt.Sprintf("seconds=%d reason=%s", secs, u.BlockReason))
	t, _ := txTimeRFC3339(ctx)
	emitEvent(ctx, "USER_BLOCKED", ChainEvent{
		Type:      "USER_BLOCKED",
		TargetID:  targetUserID,
		ActorID:   actor,
		Timestamp: t,
		Reason:    u.BlockReason,
		Detail:    u.BlockedUntil,
	})

	return nil
}

// IsUserBlocked returns whether the user is blocked
func (s *SmartContract) IsUserBlocked(ctx contractapi.TransactionContextInterface, userID string) (string, error) {
	if err := requireRole(ctx, "SecurityService"); err != nil {
		return "false", err
	}

	u, err := s.getUserProfile(ctx, userID)
	if err != nil {
		return "false", err
	}
	if u == nil {
		return "false", fmt.Errorf("user not found")
	}

	now, err := txTime(ctx)
	if err != nil {
		return "false", err
	}

	blockedNow, _ := isBlockedAt(u, now)
	if blockedNow {
		return "true", nil
	}
	return "false", nil
}

// GetUserProfile returns full user profile (owner-only or SecurityService)
func (s *SmartContract) GetUserProfile(ctx contractapi.TransactionContextInterface, userID string) (*UserProfile, error) {
	caller, _ := cid.GetID(ctx.GetStub())

	// allow self or SecurityService
	if caller != userID {
		if err := requireRole(ctx, "SecurityService"); err != nil {
			return nil, fmt.Errorf("access denied")
		}
	}
	u, err := s.getUserProfile(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Present effective (computed) block status without mutating ledger.
	now, err := txTime(ctx)
	if err == nil {
		blockedNow, expired := isBlockedAt(u, now)
		if expired {
			u.IsBlocked = false
			u.BlockedAt = ""
			u.BlockedUntil = ""
			u.BlockReason = ""
		} else {
			u.IsBlocked = blockedNow
		}
	}

	return u, nil
}

// ListBlockedUsers returns blocked users (SecurityService only)
func (s *SmartContract) ListBlockedUsers(ctx contractapi.TransactionContextInterface) ([]*UserProfile, error) {
	if err := requireRole(ctx, "SecurityService"); err != nil {
		return nil, err
	}

	iter, err := ctx.GetStub().GetStateByRange("USER_", "USER_~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var out []*UserProfile
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var u UserProfile
		if err := json.Unmarshal(kv.Value, &u); err != nil {
			continue
		}

		// compute effective block status (do not mutate ledger)
		now, _ := txTime(ctx)
		blockedNow, expired := isBlockedAt(&u, now)
		if expired {
			continue
		}
		if blockedNow {
			tmp := u
			out = append(out, &tmp)
		}
	}
	return out, nil
}

// GetAllUserProfiles returns all registered on-chain users (SecurityService only).
func (s *SmartContract) GetAllUserProfiles(ctx contractapi.TransactionContextInterface) ([]*UserProfile, error) {
	if err := requireRole(ctx, "SecurityService"); err != nil {
		return nil, err
	}

	iter, err := ctx.GetStub().GetStateByRange("USER_", "USER_~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	now, _ := txTime(ctx)
	var out []*UserProfile
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var u UserProfile
		if err := json.Unmarshal(kv.Value, &u); err != nil {
			continue
		}

		if !now.IsZero() {
			blockedNow, expired := isBlockedAt(&u, now)
			if expired {
				u.IsBlocked = false
				u.BlockedAt = ""
				u.BlockedUntil = ""
				u.BlockReason = ""
			} else {
				u.IsBlocked = blockedNow
			}
		}

		tmp := u
		out = append(out, &tmp)
	}

	sort.Slice(out, func(i, j int) bool {
		ui := strings.ToLower(strings.TrimSpace(out[i].Username))
		uj := strings.ToLower(strings.TrimSpace(out[j].Username))
		if ui == uj {
			return out[i].UserID < out[j].UserID
		}
		return ui < uj
	})

	return out, nil
}

// =====================
// Assets
// =====================

func (s *SmartContract) CreateAsset(
	ctx contractapi.TransactionContextInterface,
	id string,
	cidHash string,
	category string, // оставляем для совместимости, но НЕ доверяем
	fileHash string,
	description string,
	encryptedKeyForOwner string,
	title string,
	authors string,
	discipline string,
	licenseStr string,
	doi string,
	keywords string,
) error {
	clientID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return fmt.Errorf("failed to get client ID: %v", err)
	}

	isBlocked, _, _, err := s.checkBlocked(ctx, clientID)
	if err != nil {
		return fmt.Errorf("failed to check block status: %v", err)
	}
	if isBlocked {
		return fmt.Errorf("access denied: user is blocked")
	}

	normID, err := normalizeAssetID(id)
	if err != nil {
		return err
	}
	id = normID

	// On-chain validation (ledger is immutable; reject suspicious data early)
	cidHash = strings.TrimSpace(cidHash)
	fileHash = strings.TrimSpace(fileHash)
	description = strings.TrimSpace(description)
	encryptedKeyForOwner = strings.TrimSpace(encryptedKeyForOwner)
	title = strings.TrimSpace(title)
	authors = strings.TrimSpace(authors)
	discipline = strings.TrimSpace(discipline)
	licenseStr = strings.TrimSpace(licenseStr)
	doi = strings.TrimSpace(doi)
	keywords = strings.TrimSpace(keywords)

	if err := validateCID(cidHash); err != nil {
		return err
	}
	if err := validateFileHash(fileHash); err != nil {
		return err
	}
	if err := validateEncryptedKey(encryptedKeyForOwner); err != nil {
		return err
	}
	if err := validateTextField("title", title, maxTitleLen, true); err != nil {
		return err
	}
	if err := validateTextField("authors", authors, maxAuthorsLen, true); err != nil {
		return err
	}
	if err := validateTextField("discipline", discipline, maxDisciplineLen, true); err != nil {
		return err
	}
	if err := validateTextField("license", licenseStr, maxLicenseLen, true); err != nil {
		return err
	}
	if err := validateTextField("doi", doi, maxDOILen, true); err != nil {
		return err
	}
	if err := validateTextField("keywords", keywords, maxKeywordsLen, true); err != nil {
		return err
	}
	if err := validateTextField("description", description, maxDescriptionLen, true); err != nil {
		return err
	}

	existing, err := ctx.GetStub().GetState(id)
	if err != nil {
		return fmt.Errorf("failed to read asset: %v", err)
	}
	if existing != nil {
		return fmt.Errorf("asset %s already exists", id)
	}

	ownerUser, err := s.requireUserProfile(ctx, clientID)
	if err != nil {
		return err
	}
	ownerName := ""
	if ownerUser != nil {
		ownerName = ownerUser.Username
	}

	asset := Asset{
		ID:      id,
		CIDHash: cidHash,
		// НЕ доверяем category из UI/AI — это только после ручного approve
		Category:    "Unverified",
		FileHash:    fileHash,
		Description: description,
		OwnerID:     clientID,
		Owner:       ownerName,
		Keys: map[string]string{
			clientID: encryptedKeyForOwner,
		},
		AccessLog: []string{},
		Metadata: Metadata{
			Title:      title,
			Authors:    authors,
			Discipline: discipline,
			License:    licenseStr,
			DOI:        doi,
			Keywords:   keywords,
		},
		SuggestedCategory:      "",
		SuggestedConfidence:    0,
		NeedsManualReview:      true,
		ManualCategoryOverride: "",
	}

	b, _ := json.Marshal(asset)

	if err := ctx.GetStub().PutState(id, b); err != nil {
		return err
	}

	ts, _ := txTimeRFC3339(ctx)
	emitEvent(ctx, "ASSET_CREATED", ChainEvent{
		Type:      "ASSET_CREATED",
		AssetID:   id,
		ActorID:   clientID,
		Timestamp: ts,
	})
	_ = s.writeAuditEvent(ctx, "ASSET_CREATED", id, clientID, "", "asset created")

	return nil
}

func (s *SmartContract) GetAllAssetsPublic(ctx contractapi.TransactionContextInterface) ([]*PublicAsset, error) {
	clientID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return nil, fmt.Errorf("failed to get client ID: %v", err)
	}

	it, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer it.Close()

	var out []*PublicAsset
	for it.HasNext() {
		kv, err := it.Next()
		if err != nil {
			return nil, err
		}
		// фильтруем "USER_" и "REQ" и индексы
		if strings.HasPrefix(kv.Key, "USER_") ||
			strings.HasPrefix(kv.Key, "REQ_") ||
			strings.HasPrefix(kv.Key, "REQO_") {
			continue
		}
		if !isAssetKey(kv.Key) {
			continue
		}

		var a Asset
		if err := json.Unmarshal(kv.Value, &a); err != nil {
			continue
		}
		pub := PublicAsset{
			CIDHash:                "",
			ID:                     a.ID,
			Category:               a.Category,
			Description:            a.Description,
			Owner:                  a.Owner,
			OwnerID:                a.OwnerID, // needed by UI to determine ownership and enable Download
			Metadata:               Metadata{Title: a.Metadata.Title},
			SuggestedCategory:      a.SuggestedCategory,
			SuggestedConfidence:    a.SuggestedConfidence,
			NeedsManualReview:      a.NeedsManualReview,
			ManualCategoryOverride: a.ManualCategoryOverride,
			// CIDHash and FileHash remain hidden in public listing.
			// Full CID is returned only by ReadAsset for owner, SecurityService,
			// or users who already hold a valid encrypted key.
		}
		pub.AccessStatus = s.assetAccessStatusForViewer(ctx, &a, clientID)
		pub.CanDownload, pub.CanRequest = accessFlagsFromStatus(pub.AccessStatus)
		out = append(out, &pub)
	}
	return out, nil
}

func (s *SmartContract) GetUserProfileByUsername(ctx contractapi.TransactionContextInterface, username string) (*UserProfile, error) {
	if err := requireRole(ctx, "SecurityService"); err != nil {
		return nil, err
	}
	username = strings.TrimSpace(username)
	if err := validateTextField("username", username, maxUsernameLen, false); err != nil {
		return nil, err
	}
	u, err := s.getUserProfileByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, fmt.Errorf("user not found")
	}
	return u, nil
}

func (s *SmartContract) ListEnrollmentInvites(ctx contractapi.TransactionContextInterface) ([]*EnrollmentInvite, error) {
	if err := requireRole(ctx, "SecurityService"); err != nil {
		return nil, err
	}

	iter, err := ctx.GetStub().GetStateByRange(enrollmentInvitePrefix, enrollmentInvitePrefix+"~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var out []*EnrollmentInvite
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var invite EnrollmentInvite
		if err := json.Unmarshal(kv.Value, &invite); err != nil {
			continue
		}
		invite.Status = normalizeInviteStatus(invite.Status)
		tmp := invite
		out = append(out, &tmp)
	}
	return out, nil
}

func (s *SmartContract) IssueEnrollmentInvite(
	ctx contractapi.TransactionContextInterface,
	username string,
	department string,
	role string,
	org string,
	inviteID string,
	expiresAt string,
) error {
	if err := requireRole(ctx, "SecurityService"); err != nil {
		return err
	}

	username = strings.TrimSpace(username)
	department = strings.TrimSpace(department)
	role = strings.TrimSpace(role)
	org = strings.TrimSpace(org)
	inviteID = strings.TrimSpace(inviteID)
	expiresAt = strings.TrimSpace(expiresAt)

	if err := validateTextField("username", username, maxUsernameLen, false); err != nil {
		return err
	}
	if err := validateTextField("department", department, maxDisciplineLen, false); err != nil {
		return err
	}
	if err := validateTextField("role", role, maxCategoryLen, false); err != nil {
		return err
	}
	if err := validateTextField("org", org, maxCategoryLen, false); err != nil {
		return err
	}
	if err := validateTextField("inviteID", inviteID, maxInviteIDLen, false); err != nil {
		return err
	}
	if _, err := parseRFC3339(expiresAt); err != nil {
		return fmt.Errorf("expiresAt must be RFC3339")
	}

	if existing, err := s.getUserProfileByUsername(ctx, username); err != nil {
		return err
	} else if existing != nil {
		return fmt.Errorf("username already activated")
	}

	existingInvite, err := s.getEnrollmentInvite(ctx, username)
	if err != nil {
		return err
	}
	if existingInvite != nil && isPendingInviteStatus(existingInvite.Status) {
		return fmt.Errorf("active invite already exists for username")
	}

	now, _ := txTimeRFC3339(ctx)
	actor, _ := cid.GetID(ctx.GetStub())
	invite := &EnrollmentInvite{
		Username:     username,
		Department:   department,
		Role:         role,
		Org:          org,
		InviteID:     inviteID,
		Status:       "pending",
		IssuedAt:     now,
		ExpiresAt:    expiresAt,
		IssuedBy:     actor,
		UpdatedAt:    now,
		ReissueCount: 0,
	}
	if existingInvite != nil {
		invite.ReissueCount = existingInvite.ReissueCount
	}
	if err := s.putEnrollmentInvite(ctx, invite); err != nil {
		return err
	}
	_ = s.writeAuditEvent(ctx, "USER_INVITE_ISSUED", "", actor, "", fmt.Sprintf("username=%s inviteID=%s", username, inviteID))
	return nil
}

func (s *SmartContract) ReissueEnrollmentInvite(
	ctx contractapi.TransactionContextInterface,
	username string,
	inviteID string,
	expiresAt string,
) error {
	if err := requireRole(ctx, "SecurityService"); err != nil {
		return err
	}

	username = strings.TrimSpace(username)
	inviteID = strings.TrimSpace(inviteID)
	expiresAt = strings.TrimSpace(expiresAt)

	if err := validateTextField("username", username, maxUsernameLen, false); err != nil {
		return err
	}
	if err := validateTextField("inviteID", inviteID, maxInviteIDLen, false); err != nil {
		return err
	}
	if _, err := parseRFC3339(expiresAt); err != nil {
		return fmt.Errorf("expiresAt must be RFC3339")
	}
	if existing, err := s.getUserProfileByUsername(ctx, username); err != nil {
		return err
	} else if existing != nil {
		return fmt.Errorf("username already activated")
	}

	invite, err := s.getEnrollmentInvite(ctx, username)
	if err != nil {
		return err
	}
	if invite == nil {
		return fmt.Errorf("invite not found")
	}
	if normalizeInviteStatus(invite.Status) == "activated" {
		return fmt.Errorf("invite already activated")
	}

	now, _ := txTimeRFC3339(ctx)
	actor, _ := cid.GetID(ctx.GetStub())
	previousInviteID := invite.InviteID
	invite.PreviousInviteID = previousInviteID
	invite.InviteID = inviteID
	invite.Status = "pending"
	invite.IssuedAt = now
	invite.ExpiresAt = expiresAt
	invite.IssuedBy = actor
	invite.UpdatedAt = now
	invite.LastReissuedAt = now
	invite.ReissueCount++
	invite.ActivatedAt = ""
	invite.UserID = ""
	invite.MSPID = ""
	invite.RevokedAt = ""
	invite.RevokedBy = ""
	invite.RevokedReason = ""

	if err := s.putEnrollmentInvite(ctx, invite); err != nil {
		return err
	}
	_ = s.writeAuditEvent(ctx, "USER_INVITE_REISSUED", "", actor, "", fmt.Sprintf("username=%s oldInviteID=%s newInviteID=%s", username, previousInviteID, inviteID))
	return nil
}

func (s *SmartContract) RevokeEnrollmentInvite(
	ctx contractapi.TransactionContextInterface,
	username string,
	reason string,
) error {
	if err := requireRole(ctx, "SecurityService"); err != nil {
		return err
	}

	username = strings.TrimSpace(username)
	reason = strings.TrimSpace(reason)
	if err := validateTextField("username", username, maxUsernameLen, false); err != nil {
		return err
	}
	if err := validateTextField("reason", reason, maxReasonLen, true); err != nil {
		return err
	}
	if existing, err := s.getUserProfileByUsername(ctx, username); err != nil {
		return err
	} else if existing != nil {
		return fmt.Errorf("username already activated")
	}

	invite, err := s.getEnrollmentInvite(ctx, username)
	if err != nil {
		return err
	}
	if invite == nil {
		return fmt.Errorf("invite not found")
	}
	if !isPendingInviteStatus(invite.Status) {
		return fmt.Errorf("invite is not pending")
	}

	now, _ := txTimeRFC3339(ctx)
	actor, _ := cid.GetID(ctx.GetStub())
	invite.Status = "revoked"
	invite.UpdatedAt = now
	invite.RevokedAt = now
	invite.RevokedBy = actor
	invite.RevokedReason = reason
	if err := s.putEnrollmentInvite(ctx, invite); err != nil {
		return err
	}
	_ = s.writeAuditEvent(ctx, "USER_INVITE_REVOKED", "", actor, "", fmt.Sprintf("username=%s inviteID=%s reason=%s", username, invite.InviteID, reason))
	return nil
}

func (s *SmartContract) DeletePendingUser(
	ctx contractapi.TransactionContextInterface,
	username string,
) error {
	if err := requireRole(ctx, "SecurityService"); err != nil {
		return err
	}

	username = strings.TrimSpace(username)
	if err := validateTextField("username", username, maxUsernameLen, false); err != nil {
		return err
	}
	if existing, err := s.getUserProfileByUsername(ctx, username); err != nil {
		return err
	} else if existing != nil {
		return fmt.Errorf("username already activated")
	}

	invite, err := s.getEnrollmentInvite(ctx, username)
	if err != nil {
		return err
	}
	if invite == nil {
		return fmt.Errorf("invite not found")
	}
	if normalizeInviteStatus(invite.Status) == "activated" {
		return fmt.Errorf("invite already activated")
	}

	if err := ctx.GetStub().DelState(enrollmentInviteKey(username)); err != nil {
		return err
	}

	actor, _ := cid.GetID(ctx.GetStub())
	_ = s.writeAuditEvent(ctx, "USER_PENDING_DELETED", "", actor, "", fmt.Sprintf("username=%s lastInviteID=%s", username, invite.InviteID))
	return nil
}

func (s *SmartContract) ActivateEnrollmentInvite(
	ctx contractapi.TransactionContextInterface,
	userID string,
	username string,
	mspID string,
	publicKey string,
	fingerprint string,
	fabricCert string,
	webAuthnUserHandle string,
	webAuthnCredentialsJSON string,
	inviteID string,
) error {
	if err := requireRole(ctx, "SecurityService"); err != nil {
		return err
	}

	userID = strings.TrimSpace(userID)
	username = strings.TrimSpace(username)
	mspID = strings.TrimSpace(mspID)
	publicKey = strings.TrimSpace(publicKey)
	fingerprint = strings.TrimSpace(fingerprint)
	fabricCert = strings.TrimSpace(fabricCert)
	webAuthnUserHandle = strings.TrimSpace(webAuthnUserHandle)
	webAuthnCredentialsJSON = strings.TrimSpace(webAuthnCredentialsJSON)
	inviteID = strings.TrimSpace(inviteID)

	if err := validateTextField("userID", userID, maxFabricCertLen, false); err != nil {
		return err
	}
	if err := validateTextField("username", username, maxUsernameLen, false); err != nil {
		return err
	}
	if err := validateTextField("mspID", mspID, maxCategoryLen, false); err != nil {
		return err
	}
	if err := validateTextField("publicKey", publicKey, maxPublicKeyLen, false); err != nil {
		return err
	}
	if err := validateTextField("fingerprint", fingerprint, maxFingerprintLen, true); err != nil {
		return err
	}
	if err := validateTextField("fabricCert", fabricCert, maxFabricCertLen, false); err != nil {
		return err
	}
	if err := validateTextField("webAuthnUserHandle", webAuthnUserHandle, maxUserHandleLen, true); err != nil {
		return err
	}
	if err := validateTextField("webAuthnCredentialsJSON", webAuthnCredentialsJSON, maxCredentialsLen, false); err != nil {
		return err
	}
	if err := validateTextField("inviteID", inviteID, maxInviteIDLen, false); err != nil {
		return err
	}

	invite, err := s.getEnrollmentInvite(ctx, username)
	if err != nil {
		return err
	}
	if invite == nil {
		return fmt.Errorf("invite not found")
	}
	if !isPendingInviteStatus(invite.Status) {
		return fmt.Errorf("invite is not active")
	}
	if invite.InviteID != inviteID {
		return fmt.Errorf("invite mismatch")
	}
	expAt, err := parseRFC3339(invite.ExpiresAt)
	if err != nil {
		return fmt.Errorf("invite has invalid expiry")
	}
	now, err := txTime(ctx)
	if err != nil {
		return err
	}
	if now.After(expAt) {
		return fmt.Errorf("invite expired")
	}

	var creds []WebAuthnCredential
	if err := json.Unmarshal([]byte(webAuthnCredentialsJSON), &creds); err != nil {
		return fmt.Errorf("invalid webAuthnCredentialsJSON: %v", err)
	}
	for i := range creds {
		cred := creds[i]
		if err := validateTextField("credentialID", cred.CredentialID, maxInviteIDLen, false); err != nil {
			return err
		}
		if err := validateTextField("publicKeyPEM", cred.PublicKeyPEM, maxPublicKeyLen, false); err != nil {
			return err
		}
		if err := validateTextField("aaguid", cred.AAGUID, maxAAGUIDLen, true); err != nil {
			return err
		}
		if err := validateTextField("attestationFormat", cred.AttestationFormat, maxCategoryLen, true); err != nil {
			return err
		}
		if err := validateTextField("label", cred.Label, maxLabelLen, true); err != nil {
			return err
		}
		if err := validateTextField("rpID", cred.RPID, maxRPIDLen, true); err != nil {
			return err
		}
	}

	existing, err := s.getUserProfile(ctx, userID)
	if err != nil {
		return err
	}
	if existingByName, err := s.getUserProfileByUsername(ctx, username); err != nil {
		return err
	} else if existingByName != nil && existingByName.UserID != userID {
		return fmt.Errorf("username already mapped to another userID")
	}

	profile := &UserProfile{
		UserID:              userID,
		Username:            username,
		Department:          invite.Department,
		Role:                invite.Role,
		MSPID:               mspID,
		PublicKey:           publicKey,
		Fingerprint:         fingerprint,
		FabricCert:          fabricCert,
		WebAuthnUserHandle:  webAuthnUserHandle,
		WebAuthnCredentials: creds,
		CreatedAt:           now.Format(time.RFC3339),
		UpdatedAt:           now.Format(time.RFC3339),
		WebAuthnIdentity: WebAuthnIdentity{
			UserHandle:      webAuthnUserHandle,
			Credentials:     creds,
			CredentialCount: len(creds),
			LastUpdatedAt:   now.Format(time.RFC3339),
		},
		FabricSigningIdentity: FabricSigningIdentity{
			MSPID:         mspID,
			Certificate:   fabricCert,
			Algorithm:     "ECDSA-P256",
			LastUpdatedAt: now.Format(time.RFC3339),
		},
		DataEncryptionIdentity: DataEncryptionIdentity{
			PublicKey:     publicKey,
			Fingerprint:   fingerprint,
			Algorithm:     dataEncryptionAlgorithmForPublicKey(publicKey),
			LastUpdatedAt: now.Format(time.RFC3339),
		},
		RecoveryBundle: RecoveryBundleStatus{
			Required:      true,
			Created:       false,
			UpdatedAt:     now.Format(time.RFC3339),
			BundleVersion: 1,
			Protection:    "Argon2id+Aes256Gcm",
		},
		IsBlocked: false,
	}
	if existing != nil {
		profile.IsBlocked = existing.IsBlocked
		profile.BlockedAt = existing.BlockedAt
		profile.BlockedUntil = existing.BlockedUntil
		profile.BlockReason = existing.BlockReason
		if strings.TrimSpace(existing.CreatedAt) != "" {
			profile.CreatedAt = existing.CreatedAt
		}
	}
	if err := s.putUserProfile(ctx, profile); err != nil {
		return err
	}

	actor, _ := cid.GetID(ctx.GetStub())
	invite.Status = "activated"
	invite.ActivatedAt = now.Format(time.RFC3339)
	invite.UserID = userID
	invite.MSPID = mspID
	invite.UpdatedAt = now.Format(time.RFC3339)
	if err := s.putEnrollmentInvite(ctx, invite); err != nil {
		return err
	}
	_ = s.writeAuditEvent(ctx, "USER_ACTIVATED", "", actor, userID, fmt.Sprintf("username=%s", username))
	return nil
}

func (s *SmartContract) SyncWebAuthnCredentials(
	ctx contractapi.TransactionContextInterface,
	username string,
	webAuthnUserHandle string,
	webAuthnCredentialsJSON string,
) error {
	if err := requireRole(ctx, "SecurityService"); err != nil {
		return err
	}
	username = strings.TrimSpace(username)
	webAuthnUserHandle = strings.TrimSpace(webAuthnUserHandle)
	webAuthnCredentialsJSON = strings.TrimSpace(webAuthnCredentialsJSON)

	if err := validateTextField("username", username, maxUsernameLen, false); err != nil {
		return err
	}
	if err := validateTextField("webAuthnUserHandle", webAuthnUserHandle, maxUserHandleLen, true); err != nil {
		return err
	}
	if err := validateTextField("webAuthnCredentialsJSON", webAuthnCredentialsJSON, maxCredentialsLen, false); err != nil {
		return err
	}

	u, err := s.getUserProfileByUsername(ctx, username)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("user not found")
	}

	var creds []WebAuthnCredential
	if err := json.Unmarshal([]byte(webAuthnCredentialsJSON), &creds); err != nil {
		return fmt.Errorf("invalid webAuthnCredentialsJSON: %v", err)
	}
	now, _ := txTimeRFC3339(ctx)
	u.WebAuthnUserHandle = webAuthnUserHandle
	u.WebAuthnCredentials = creds
	u.UpdatedAt = now
	u.WebAuthnIdentity = WebAuthnIdentity{
		UserHandle:      webAuthnUserHandle,
		Credentials:     creds,
		CredentialCount: len(creds),
		LastUpdatedAt:   now,
	}

	if err := s.putUserProfile(ctx, u); err != nil {
		return err
	}
	return nil
}

func (s *SmartContract) MarkRecoveryBundleCreated(
	ctx contractapi.TransactionContextInterface,
	createdAt string,
	bundleVersion string,
	protection string,
) error {
	userID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return fmt.Errorf("failed to get client ID: %v", err)
	}
	createdAt = strings.TrimSpace(createdAt)
	bundleVersion = strings.TrimSpace(bundleVersion)
	protection = strings.TrimSpace(protection)
	if createdAt != "" {
		if _, err := parseRFC3339(createdAt); err != nil {
			return fmt.Errorf("createdAt must be RFC3339")
		}
	}
	if err := validateTextField("bundleVersion", bundleVersion, 32, false); err != nil {
		return err
	}
	if err := validateTextField("protection", protection, 128, false); err != nil {
		return err
	}
	if blocked, _, _, err := s.checkBlocked(ctx, userID); err != nil {
		return err
	} else if blocked {
		return fmt.Errorf("access denied: user is blocked")
	}

	version, err := strconv.Atoi(bundleVersion)
	if err != nil || version <= 0 {
		return fmt.Errorf("bundleVersion must be positive integer")
	}
	u, err := s.requireUserProfile(ctx, userID)
	if err != nil {
		return err
	}
	now, _ := txTimeRFC3339(ctx)
	if createdAt == "" {
		createdAt = now
	}
	u.UpdatedAt = now
	u.RecoveryBundle.Required = true
	u.RecoveryBundle.Created = true
	u.RecoveryBundle.CreatedAt = createdAt
	u.RecoveryBundle.UpdatedAt = now
	u.RecoveryBundle.BundleVersion = version
	u.RecoveryBundle.Protection = protection
	if err := s.putUserProfile(ctx, u); err != nil {
		return err
	}
	_ = s.writeAuditEvent(ctx, "RECOVERY_BUNDLE_CREATED", "", userID, userID, fmt.Sprintf("createdAt=%s version=%d protection=%s", createdAt, version, protection))
	return nil
}

func (s *SmartContract) ReadAsset(ctx contractapi.TransactionContextInterface, id string) (*Asset, error) {
	clientID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return nil, fmt.Errorf("failed to get client ID: %v", err)
	}

	normID, err := normalizeAssetID(id)
	if err != nil {
		return nil, err
	}
	id = normID

	assetJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read asset: %v", err)
	}
	if assetJSON == nil {
		return nil, fmt.Errorf("asset not found")
	}

	var a Asset
	if err := json.Unmarshal(assetJSON, &a); err != nil {
		return nil, fmt.Errorf("failed to unmarshal asset: %v", err)
	}

	// owner can see full
	if a.OwnerID == clientID {
		return &a, nil
	}
	// SecurityService can see full
	if err := requireRole(ctx, "SecurityService"); err == nil {
		return &a, nil
	}

	// everyone else: check whether they currently hold a valid encrypted key.
	// IMPORTANT: do not leak key material, access logs, or sensitive provenance data.
	pub := a
	pub.Keys = map[string]string{}
	pub.AccessLog = []string{}

	hasAccess := false
	if a.Keys != nil {
		if resolvedKey, ok := resolveUserKeyInMap(a.Keys, clientID); ok {
			if strings.TrimSpace(a.Keys[resolvedKey]) != "" {
				hasAccess = true
			}
		}
	}

	if !hasAccess {
		// Strip sensitive provenance and metadata — show only public summary.
		pub.CIDHash = ""
		pub.FileHash = ""
		pub.OwnerID = ""
		pub.Metadata = Metadata{
			Title: a.Metadata.Title,
			// Authors, Discipline, License, DOI, Keywords are hidden
		}
	}

	return &pub, nil
}

func (s *SmartContract) GetMyAssets(ctx contractapi.TransactionContextInterface) ([]*Asset, error) {
	clientID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return nil, fmt.Errorf("failed to get client ID: %v", err)
	}

	it, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer it.Close()

	var assets []*Asset
	for it.HasNext() {
		kv, err := it.Next()
		if err != nil {
			return nil, err
		}

		if !isAssetKey(kv.Key) {
			continue
		}

		var asset Asset
		if err := json.Unmarshal(kv.Value, &asset); err != nil {
			continue
		}
		if asset.OwnerID == clientID {
			assets = append(assets, &asset)
		}
	}
	return assets, nil
}

func (s *SmartContract) GetAllAssets(ctx contractapi.TransactionContextInterface) ([]*Asset, error) {
	if err := requireRole(ctx, "SecurityService"); err != nil {
		return nil, fmt.Errorf("access denied: only SecurityService can call GetAllAssets")
	}

	it, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer it.Close()

	var assets []*Asset
	for it.HasNext() {
		kv, err := it.Next()
		if err != nil {
			return nil, err
		}

		if !isAssetKey(kv.Key) {
			continue
		}

		var asset Asset
		if err := json.Unmarshal(kv.Value, &asset); err != nil {
			continue
		}
		assets = append(assets, &asset)
	}
	return assets, nil
}

// =====================
// Access requests / keys
// =====================

type RequestResult struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func (s *SmartContract) RequestAccess(ctx contractapi.TransactionContextInterface, assetID string) (map[string]string, error) {
	return s.RequestAccessWithReason(ctx, assetID, "")
}

func (s *SmartContract) RequestAccessWithReason(ctx contractapi.TransactionContextInterface, assetID string, reason string) (map[string]string, error) {
	// normalizeAssetID теперь возвращает (string, error)
	normalized, err := normalizeAssetID(assetID)
	if err != nil {
		return nil, err
	}
	assetID = normalized

	requesterID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return nil, fmt.Errorf("failed to get requester id: %v", err)
	}

	// block check (SecurityService may block users)
	isBlocked, blockReason, blockedUntil, err := s.checkBlocked(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("failed to check block status: %v", err)
	}
	if isBlocked {
		// IMPORTANT: return ok:true + {status:"DENIED"} for the API, but also EMIT an event
		// so that the risk engine can observe blocked attempts.
		now, _ := txTimeRFC3339(ctx)
		emitEvent(ctx, "ACCESS_DENIED", ChainEvent{
			Type:      "ACCESS_DENIED",
			AssetID:   assetID,
			ActorID:   requesterID,
			TargetID:  requesterID,
			Status:    "DENIED",
			Timestamp: now,
			Reason:    blockReason,
			Detail:    "USER_BLOCKED until " + blockedUntil,
		})
		return map[string]string{"status": "DENIED", "message": "access denied: user is blocked"}, nil
	}

	// requester must be registered
	if _, err := s.requireUserProfile(ctx, requesterID); err != nil {
		_ = s.writeAuditEvent(ctx, "ACCESS_REQUEST_DENIED", assetID, requesterID, "", "user not registered")
		return map[string]string{"status": "DENIED", "message": err.Error()}, nil
	}

	// читаем ассет как RAW (нам нужны owner + category + Keys)
	asset, err := s.readAssetRaw(ctx, assetID)
	if err != nil {
		// Important: do not fail the whole invoke with 500 for a simple "asset not found".
		// Treat as a denied access attempt so UX is stable and the risk engine can see scanning attempts.
		if isNotFoundErr(err) {
			_ = s.writeAuditEvent(ctx, "ACCESS_REQUEST_DENIED", assetID, requesterID, "", "asset not found")
			return map[string]string{"status": "DENIED", "message": "asset not found"}, nil
		}
		return nil, err
	}

	assetOwnerID := asset.OwnerID
	assetCategory := strings.TrimSpace(asset.Category)

	// если доступ уже есть — сразу APPROVED (не создаём новую заявку)
	if asset.Keys != nil {
		if k, ok := resolveUserKeyInMap(asset.Keys, requesterID); ok {
			if strings.TrimSpace(asset.Keys[k]) != "" {
				_ = s.writeAuditEvent(ctx, "ACCESS_ALREADY_GRANTED", assetID, requesterID, "", "already has key")
				return map[string]string{"status": "APPROVED", "message": "already has access"}, nil
			}
		}
	}

	if strings.TrimSpace(assetCategory) == "" {
		assetCategory = "UNKNOWN"
	}

	dept := ""
	if v, found, _ := cid.GetAttributeValue(ctx.GetStub(), "department"); found {
		dept = strings.TrimSpace(v)
	}
	role := ""
	if v, found, _ := cid.GetAttributeValue(ctx.GetStub(), "role"); found {
		role = strings.TrimSpace(v)
	}

	if strings.TrimSpace(dept) == "" {
		dept = "UNKNOWN"
	}

	reason = strings.TrimSpace(reason)

	// =====================
	// ABAC v1 (minimal prototype):
	// - policy: dept(from cert) + approved category
	// - if category Unverified/UNKNOWN -> do not auto-deny (manual owner review)
	// - SecurityService bypasses policy
	// - owner bypasses policy
	// =====================
	if !strings.EqualFold(role, "SecurityService") && requesterID != assetOwnerID {
		if !policyAllowsDepartment(dept, assetCategory) {
			now, _ := txTimeRFC3339(ctx)
			reqK, _ := reqKey(ctx, assetID, requesterID)
			deniedReq := AccessRequest{
				Department:    dept,
				AssetCategory: assetCategory,
				AssetID:       assetID,
				RequesterID:   requesterID,
				Requester:     requesterID,
				Status:        "DENIED",
				Reason:        "ABAC_POLICY_DENY",
				CreatedAt:     now,
				UpdatedAt:     now,
			}
			nb, _ := json.Marshal(deniedReq)
			_ = ctx.GetStub().PutState(reqK, nb)

			// Do NOT create owner-index entry for denied requests (avoid ledger bloat).
			idx, _ := reqOwnerIndexKey(ctx, assetOwnerID, assetID, requesterID)
			_ = ctx.GetStub().DelState(idx)

			emitEvent(ctx, "ACCESS_DENIED", ChainEvent{
				Type:      "ACCESS_DENIED",
				AssetID:   assetID,
				ActorID:   requesterID,
				TargetID:  requesterID,
				Status:    "DENIED",
				Timestamp: now,
				Detail:    "ABAC_POLICY_DENY",
			})

			_ = s.writeAuditEvent(ctx, "ACCESS_REQUEST_DENIED", assetID, requesterID, assetOwnerID, "ABAC_POLICY_DENY")

			return map[string]string{"status": "DENIED", "message": "ABAC policy denied"}, nil
		}
	}

	reqK, _ := reqKey(ctx, assetID, requesterID)

	b, err := ctx.GetStub().GetState(reqK)
	if err != nil {
		return nil, err
	}

	now, err := txTimeRFC3339(ctx)
	if err != nil {
		return nil, err
	}

	// есть старая заявка
	if len(b) != 0 {
		var req AccessRequest
		if err := json.Unmarshal(b, &req); err != nil {
			return nil, err
		}

		// гарантируем поля, чтобы schema не ругалась
		if strings.TrimSpace(req.Department) == "" {
			req.Department = dept
		}
		if strings.TrimSpace(req.AssetCategory) == "" {
			req.AssetCategory = assetCategory
		}

		switch strings.ToUpper(strings.TrimSpace(req.Status)) {
		case "PENDING":
			// уже pending
			nb, _ := json.Marshal(req)
			_ = ctx.GetStub().PutState(reqK, nb)
			return map[string]string{"status": "PENDING", "message": "request already pending"}, nil

		case "REVOKED", "DENIED", "CANCELLED":
			// reopen
			req.Status = "PENDING"
			req.UpdatedAt = now
			if reason != "" {
				req.Reason = reason
			}

			// на всякий: ключевые поля
			if strings.TrimSpace(req.AssetID) == "" {
				req.AssetID = assetID
			}
			if strings.TrimSpace(req.RequesterID) == "" {
				req.RequesterID = requesterID
			}

			nb, _ := json.Marshal(req)
			if err := ctx.GetStub().PutState(reqK, nb); err != nil {
				return nil, err
			}

			idx, _ := reqOwnerIndexKey(ctx, assetOwnerID, assetID, requesterID)
			_ = ctx.GetStub().PutState(idx, []byte{0x00})

			emitEvent(ctx, "ACCESS_REQUEST_REOPENED", ChainEvent{
				Type:      "ACCESS_REQUEST_REOPENED",
				AssetID:   assetID,
				ActorID:   requesterID,
				Status:    "PENDING",
				Timestamp: now,
				Detail:    "request reopened",
			})
			_ = s.writeAuditEvent(ctx, "ACCESS_REQUEST_REOPENED", assetID, requesterID, assetOwnerID, "request reopened")

			return map[string]string{"status": "PENDING", "message": "request reopened"}, nil

		case "APPROVED":
			// After RotateAssetContent the asset.Keys map is cleared, but old requests may stay APPROVED.
			// Treat APPROVED as valid only if the requester currently has an encrypted key in asset.Keys.
			hasKey := false
			if asset.Keys != nil {
				if k, ok := resolveUserKeyInMap(asset.Keys, requesterID); ok {
					if strings.TrimSpace(asset.Keys[k]) != "" {
						hasKey = true
					}
				}
			}
			if hasKey {
				return map[string]string{"status": "APPROVED", "message": "already approved"}, nil
			}

			// Re-open as PENDING: approval flag exists but no key is present (rotation/revocation).
			req.Status = "PENDING"
			req.UpdatedAt = now
			if reason != "" {
				req.Reason = reason
			}
			// ensure key fields for schema / indexing
			if strings.TrimSpace(req.AssetID) == "" {
				req.AssetID = assetID
			}
			if strings.TrimSpace(req.RequesterID) == "" {
				req.RequesterID = requesterID
			}
			if strings.TrimSpace(req.Requester) == "" {
				req.Requester = requesterID
			}
			if strings.TrimSpace(req.AssetCategory) == "" {
				req.AssetCategory = assetCategory
			}

			nb, _ := json.Marshal(req)
			if err := ctx.GetStub().PutState(reqK, nb); err != nil {
				return nil, err
			}

			idx, _ := reqOwnerIndexKey(ctx, assetOwnerID, assetID, requesterID)
			_ = ctx.GetStub().PutState(idx, []byte{0x00})

			emitEvent(ctx, "ACCESS_REQUEST_REOPENED", ChainEvent{
				Type:      "ACCESS_REQUEST_REOPENED",
				AssetID:   assetID,
				ActorID:   requesterID,
				Status:    "PENDING",
				Timestamp: now,
				Detail:    "approved-but-missing-key; reopened",
			})
			_ = s.writeAuditEvent(ctx, "ACCESS_REQUEST_REOPENED", assetID, requesterID, assetOwnerID, "approved-but-missing-key; reopened")

			return map[string]string{"status": "PENDING", "message": "approved but key missing; reopened"}, nil
		default:
			// неизвестный статус — пересоздадим как PENDING
			req.Status = "PENDING"
			req.UpdatedAt = now
			nb, _ := json.Marshal(req)
			_ = ctx.GetStub().PutState(reqK, nb)
			return map[string]string{"status": "PENDING", "message": "request reset to pending"}, nil
		}
	}

	// новой заявки нет — создаём
	req := AccessRequest{
		Department:    dept,
		AssetCategory: assetCategory,
		AssetID:       assetID,
		RequesterID:   requesterID,
		Requester:     requesterID,
		Status:        "PENDING",
		Reason:        reason,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	nb, _ := json.Marshal(req)
	if err := ctx.GetStub().PutState(reqK, nb); err != nil {
		return nil, err
	}

	idx, _ := reqOwnerIndexKey(ctx, assetOwnerID, assetID, requesterID)
	_ = ctx.GetStub().PutState(idx, []byte{0x00})

	emitEvent(ctx, "ACCESS_REQUEST_CREATED", ChainEvent{
		Type:      "ACCESS_REQUEST_CREATED",
		AssetID:   assetID,
		ActorID:   requesterID,
		Status:    "PENDING",
		Timestamp: now,
		Detail:    "request created",
	})
	_ = s.writeAuditEvent(ctx, "ACCESS_REQUEST_CREATED", assetID, requesterID, assetOwnerID, "request created")

	return map[string]string{"status": "PENDING", "message": "request created"}, nil
}

func (s *SmartContract) CancelMyRequest(ctx contractapi.TransactionContextInterface, assetID string) error {
	requesterID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return fmt.Errorf("failed to get client ID: %v", err)
	}

	// Normalize asset id (RequestAccess uses normalized form when storing requests).
	assetNorm, nerr := normalizeAssetID(assetID)
	if nerr != nil {
		return nerr
	}
	assetID = assetNorm

	// Block check (a blocked user must not mutate ledger state).
	isBlocked, _, _, err := s.checkBlocked(ctx, requesterID)
	if err != nil {
		return fmt.Errorf("failed to check block status: %v", err)
	}
	if isBlocked {
		return fmt.Errorf("access denied: user is blocked")
	}

	key, _ := reqKey(ctx, assetID, requesterID)
	reqBytes, err := ctx.GetStub().GetState(key)
	if err != nil || reqBytes == nil {
		return fmt.Errorf("request not found")
	}

	var req AccessRequest
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return fmt.Errorf("failed to unmarshal request: %v", err)
	}
	if strings.ToUpper(strings.TrimSpace(req.Status)) != "PENDING" {
		return fmt.Errorf("can cancel only PENDING request, current=%s", req.Status)
	}

	assetBytes, err := ctx.GetStub().GetState(assetID)
	if err != nil || assetBytes == nil {
		return fmt.Errorf("asset not found")
	}
	var asset Asset
	if err := json.Unmarshal(assetBytes, &asset); err != nil {
		return fmt.Errorf("failed to unmarshal asset: %v", err)
	}

	t, _ := txTimeRFC3339(ctx)
	req.Status = "CANCELLED"
	req.Reason = "Cancelled by requester"
	req.UpdatedAt = t

	nb, _ := json.Marshal(req)
	if err := ctx.GetStub().PutState(key, nb); err != nil {
		return err
	}

	// Remove owner pending index entry (if present).
	idx, _ := reqOwnerIndexKey(ctx, asset.OwnerID, assetID, requesterID)
	_ = ctx.GetStub().DelState(idx)

	// Ledger audit: ACCESS_REQUEST_CANCELLED
	_ = s.writeAuditEvent(ctx, "ACCESS_REQUEST_CANCELLED", assetID, requesterID, "", "")
	return nil
}

// owner grants access by storing encrypted key for requester
func (s *SmartContract) GrantAccess(ctx contractapi.TransactionContextInterface, assetID string, requesterID string, encryptedKeyForRequester string) error {
	ownerID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return fmt.Errorf("failed to get owner identity: %v", err)
	}
	if strings.TrimSpace(requesterID) == "" {
		return fmt.Errorf("requesterID must not be empty")
	}
	if strings.TrimSpace(encryptedKeyForRequester) == "" {
		return fmt.Errorf("encryptedKeyForRequester must not be empty")
	}
	if err := validateEncryptedKey(encryptedKeyForRequester); err != nil {
		return err
	}

	assetNorm, nerr := normalizeAssetID(assetID)
	if nerr == nil {
		assetID = assetNorm
	}

	isBlocked, _, _, err := s.checkBlocked(ctx, ownerID)
	if err != nil {
		return fmt.Errorf("failed to check block status: %v", err)
	}
	if isBlocked {
		return fmt.Errorf("access denied: user is blocked")
	}

	assetBytes, err := ctx.GetStub().GetState(assetID)
	if err != nil {
		return fmt.Errorf("failed to get asset: %v", err)
	}
	if assetBytes == nil {
		return fmt.Errorf("asset does not exist")
	}

	var asset Asset
	if err := json.Unmarshal(assetBytes, &asset); err != nil {
		return fmt.Errorf("failed to unmarshal asset: %v", err)
	}
	if asset.OwnerID != ownerID {
		return fmt.Errorf("only owner can grant access")
	}

	// Governance: do not allow granting access until category is approved (manual review finished).
	// SecurityService bypass (if ever used as owner).
	ownerRole := ""
	if v, found, _ := cid.GetAttributeValue(ctx.GetStub(), "role"); found {
		ownerRole = strings.TrimSpace(v)
	}
	catLower := strings.ToLower(strings.TrimSpace(asset.Category))
	// SecurityService can grant even if category is pending review (operational override).
	// For normal owners, require category to be approved (i.e., not Unverified/empty and not NeedsManualReview).
	if !strings.EqualFold(ownerRole, "SecurityService") {
		if asset.NeedsManualReview || catLower == "unverified" || catLower == "" {
			return fmt.Errorf("category is not approved yet; call ApproveCategory before granting access")
		}
	}
	// 1) строго: должна быть заявка PENDING (или доступ уже выдан ранее — тогда идемпотентно OK)
	rk, _ := reqKey(ctx, assetID, requesterID)
	reqBytes, err := ctx.GetStub().GetState(rk)
	if err != nil {
		return fmt.Errorf("failed to read request: %v", err)
	}
	if reqBytes == nil {
		// Try to resolve requesterID by scanning existing requests for this asset.
		candidates := make(map[string]string)

		// 1) Scan request keys: REQ_<assetID>_<requesterID>
		reqPrefix := "REQ_" + assetID + "_"
		startKey := reqPrefix
		endKey := reqPrefix + string(rune(0x10FFFF))
		it2, itErr2 := ctx.GetStub().GetStateByRange(startKey, endKey)
		if itErr2 != nil {
			return fmt.Errorf("failed to scan requests: %v", itErr2)
		}
		for it2.HasNext() {
			kv, e := it2.Next()
			if e != nil {
				_ = it2.Close()
				return fmt.Errorf("failed to iterate requests: %v", e)
			}
			if strings.HasPrefix(kv.Key, reqPrefix) {
				rid := strings.TrimSpace(kv.Key[len(reqPrefix):])
				if rid != "" {
					candidates[rid] = ""
				}
			}
		}
		_ = it2.Close()

		// 2) Fallback: scan owner-index keys (REQO_<ownerID>_<assetID>_<requesterID>)
		if len(candidates) == 0 {
			ownerRaw := ownerID
			ownerB64 := base64.StdEncoding.EncodeToString([]byte(ownerRaw))
			prefixes := []string{
				"REQO_" + ownerRaw + "_" + assetID + "_",
				"REQO_" + ownerB64 + "_" + assetID + "_",
			}
			for _, pfx := range prefixes {
				it3, itErr3 := ctx.GetStub().GetStateByRange(pfx, pfx+string(rune(0x10FFFF)))
				if itErr3 != nil {
					continue
				}
				for it3.HasNext() {
					kv, e := it3.Next()
					if e != nil {
						_ = it3.Close()
						break
					}
					rid := strings.TrimSpace(kv.Key[len(pfx):])
					if rid != "" {
						candidates[rid] = ""
					}
				}
				_ = it3.Close()
			}
		}

		if resolved, ok := resolveUserKeyInMap(candidates, requesterID); ok {
			requesterID = resolved
			rk, _ = reqKey(ctx, assetID, requesterID)
			reqBytes, err = ctx.GetStub().GetState(rk)
			if err != nil {
				return fmt.Errorf("failed to read request: %v", err)
			}
		}
	}
	if reqBytes == nil {
		// If key already exists (access already granted earlier), succeed idempotently.
		if asset.Keys != nil {
			if resolvedKey, ok := resolveUserKeyInMap(asset.Keys, requesterID); ok {
				if strings.TrimSpace(asset.Keys[resolvedKey]) != "" {
					return nil
				}
			}
		}
		return fmt.Errorf("request not found")
	}
	var req AccessRequest
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return fmt.Errorf("failed to unmarshal request: %v", err)
	}
	// Idempotency: if the requester already has a key for this asset, GrantAccess is a no-op.
	if asset.Keys != nil {
		if v, ok := asset.Keys[requesterID]; ok && strings.TrimSpace(v) != "" {
			return nil
		}
		if resolvedKey, ok := resolveUserKeyInMap(asset.Keys, requesterID); ok {
			if strings.TrimSpace(asset.Keys[resolvedKey]) != "" {
				return nil
			}
		}
	}

	// Allow PENDING (normal flow) and APPROVED (idempotent re-grant / key re-attach if missing).
	if req.Status == "DENIED" {
		return fmt.Errorf("request is DENIED; reopen request before granting access")
	}
	if req.Status != "PENDING" && req.Status != "APPROVED" {
		return fmt.Errorf("request must be PENDING or APPROVED, current=%s", req.Status)
	}
	// recipient must be registered (we need a public key to deliver the encrypted key)
	_, err = s.requireUserProfile(ctx, requesterID)
	if err != nil {
		return err
	}

	// Enforce ABAC also on GrantAccess (strict mode).
	// IMPORTANT: we use req.Department (taken from requester's certificate at RequestAccess time).
	if !isManualReviewCategory(asset.Category) && !policyAllowsDepartment(req.Department, asset.Category) {
		return fmt.Errorf("ABAC_POLICY_DENY: department=%s category=%s", req.Department, asset.Category)
	}

	ts, _ := txTimeRFC3339(ctx)

	// 2) обновляем заявку
	req.Status = "APPROVED"
	req.Reason = "Approved by owner"
	req.UpdatedAt = ts
	nb, _ := json.Marshal(req)
	if err := ctx.GetStub().PutState(rk, nb); err != nil {
		return err
	}

	// 3) ключ для requester в asset.Keys
	if asset.Keys == nil {
		asset.Keys = map[string]string{}
	}
	asset.Keys[requesterID] = encryptedKeyForRequester

	// 4) чистим индекс заявок владельца (чтобы не висело в pending)
	idx, _ := reqOwnerIndexKey(ctx, asset.OwnerID, assetID, requesterID)
	_ = ctx.GetStub().DelState(idx)

	asset.AccessLog = append(asset.AccessLog, fmt.Sprintf("[%s] ACCESS GRANTED to %s", ts, requesterID))

	updatedJSON, _ := json.Marshal(asset)
	if err := ctx.GetStub().PutState(assetID, updatedJSON); err != nil {
		return err
	}

	emitEvent(ctx, "ACCESS_GRANTED", ChainEvent{
		Type:      "ACCESS_GRANTED",
		AssetID:   assetID,
		ActorID:   ownerID,
		TargetID:  requesterID,
		Status:    "APPROVED",
		Timestamp: ts,
	})
	_ = s.writeAuditEvent(ctx, "ACCESS_GRANTED", assetID, ownerID, requesterID, "granted by owner")

	return nil
}

func (s *SmartContract) DenyAccess(ctx contractapi.TransactionContextInterface, assetID string, requesterID string, reason string) error {
	ownerID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return fmt.Errorf("failed to get client ID: %v", err)
	}

	isBlocked, _, _, err := s.checkBlocked(ctx, ownerID)
	if err != nil {
		return fmt.Errorf("failed to check block status: %v", err)
	}
	if isBlocked {
		return fmt.Errorf("access denied: user is blocked")
	}
	assetNorm, err := normalizeAssetID(assetID)
	if err == nil {
		assetID = assetNorm
	}

	assetBytes, err := ctx.GetStub().GetState(assetID)
	if err != nil {
		return fmt.Errorf("failed to read asset: %v", err)
	}
	if assetBytes == nil {
		return fmt.Errorf("asset not found")
	}

	var asset Asset
	if err := json.Unmarshal(assetBytes, &asset); err != nil {
		return fmt.Errorf("failed to unmarshal asset: %v", err)
	}

	if asset.OwnerID != ownerID {
		return fmt.Errorf("only owner can deny")
	}
	if strings.TrimSpace(reason) == "" {
		reason = "Denied by owner"
	}

	canonRequesterID, rk, rb, err := resolveRequestForAsset(ctx, assetID, ownerID, requesterID)
	if err != nil {
		return err
	}
	if rb == nil {
		return fmt.Errorf("request not found")
	}
	var req AccessRequest
	if err := json.Unmarshal(rb, &req); err != nil {
		return fmt.Errorf("failed to unmarshal request: %v", err)
	}
	if req.Status != "PENDING" {
		return fmt.Errorf("request must be PENDING to deny, current=%s", req.Status)
	}

	t, _ := txTimeRFC3339(ctx)
	req.Status = "DENIED"
	req.Reason = reason
	req.UpdatedAt = t

	nb, _ := json.Marshal(req)
	if err := ctx.GetStub().PutState(rk, nb); err != nil {
		return err
	}

	// cleanup owner pending index (request is no longer pending)
	idx, _ := reqOwnerIndexKey(ctx, asset.OwnerID, assetID, canonRequesterID)
	_ = ctx.GetStub().DelState(idx)

	// Ledger audit: ACCESS_DENIED
	_ = s.writeAuditEvent(ctx, "ACCESS_DENIED", assetID, ownerID, canonRequesterID, reason)

	emitEvent(ctx, "ACCESS_DENIED", ChainEvent{
		Type:      "ACCESS_DENIED",
		AssetID:   assetID,
		ActorID:   ownerID,
		TargetID:  canonRequesterID,
		Status:    "DENIED",
		Timestamp: t,
		Detail:    reason,
	})

	return nil
}

// ReopenRequest allows the asset owner to reopen a previously denied request (DENIED -> PENDING).
// Args: assetID, requester (canonical requesterID or alias/base64/x509), reason (optional).
func (s *SmartContract) ReopenRequest(ctx contractapi.TransactionContextInterface, assetID string, requester string, reason string) error {
	ownerID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return fmt.Errorf("failed to get client ID: %v", err)
	}

	isBlocked, _, _, err := s.checkBlocked(ctx, ownerID)
	if err != nil {
		return fmt.Errorf("failed to check block status: %v", err)
	}
	if isBlocked {
		return fmt.Errorf("access denied: user is blocked")
	}

	if strings.TrimSpace(assetID) == "" {
		return fmt.Errorf("assetID must not be empty")
	}
	if strings.TrimSpace(requester) == "" {
		return fmt.Errorf("requester must not be empty")
	}

	assetNorm, nerr := normalizeAssetID(assetID)
	if nerr == nil {
		assetID = assetNorm
	}

	assetBytes, err := ctx.GetStub().GetState(assetID)
	if err != nil {
		return fmt.Errorf("failed to read asset: %v", err)
	}
	if assetBytes == nil {
		return fmt.Errorf("asset not found")
	}

	var asset Asset
	if err := json.Unmarshal(assetBytes, &asset); err != nil {
		return fmt.Errorf("failed to unmarshal asset: %v", err)
	}

	if asset.OwnerID != ownerID {
		return fmt.Errorf("only owner can reopen")
	}

	now, err := txTimeRFC3339(ctx)
	if err != nil {
		return err
	}

	canonRequesterID, rk, rb, err := resolveRequestForAsset(ctx, assetID, ownerID, requester)
	if err != nil {
		return err
	}
	if rb == nil {
		return fmt.Errorf("request not found")
	}

	var req AccessRequest
	if err := json.Unmarshal(rb, &req); err != nil {
		return fmt.Errorf("failed to unmarshal request: %v", err)
	}

	if req.Status == "APPROVED" {
		return fmt.Errorf("request is already APPROVED")
	}
	if req.Status != "DENIED" && req.Status != "PENDING" {
		return fmt.Errorf("request must be DENIED or PENDING to reopen, current=%s", req.Status)
	}

	// set pending
	req.Status = "PENDING"
	if strings.TrimSpace(reason) != "" {
		req.Reason = reason
	} else if strings.TrimSpace(req.Reason) == "" {
		req.Reason = "request reopened"
	}
	req.UpdatedAt = now

	nb, _ := json.Marshal(req)
	if err := ctx.GetStub().PutState(rk, nb); err != nil {
		return err
	}

	// restore owner pending index
	idx, _ := reqOwnerIndexKey(ctx, asset.OwnerID, assetID, canonRequesterID)
	_ = ctx.GetStub().PutState(idx, []byte{0x00})

	_ = s.writeAuditEvent(ctx, "ACCESS_REQUEST_REOPENED", assetID, ownerID, canonRequesterID, "request reopened")

	emitEvent(ctx, "ACCESS_REQUEST_REOPENED", ChainEvent{
		Type:      "ACCESS_REQUEST_REOPENED",
		AssetID:   assetID,
		ActorID:   ownerID,
		TargetID:  canonRequesterID,
		Status:    "PENDING",
		Timestamp: now,
		Detail:    "request reopened",
	})

	return nil
}

func (s *SmartContract) RevokeAccess(ctx contractapi.TransactionContextInterface, assetID string, requester string, reason string) error {
	ownerID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return fmt.Errorf("failed to get client ID: %v", err)
	}

	isBlocked, _, _, err := s.checkBlocked(ctx, ownerID)
	if err != nil {
		return fmt.Errorf("failed to check block status: %v", err)
	}
	if isBlocked {
		return fmt.Errorf("access denied: user is blocked")
	}

	assetNorm, err := normalizeAssetID(assetID)
	if err == nil {
		assetID = assetNorm
	}

	requester = strings.TrimSpace(requester)
	if requester == "" {
		return fmt.Errorf("requester must not be empty")
	}

	// Read asset
	assetBytes, err := ctx.GetStub().GetState(assetID)
	if err != nil {
		return fmt.Errorf("failed to read asset: %v", err)
	}
	if assetBytes == nil {
		return fmt.Errorf("asset not found")
	}
	var asset Asset
	if err := json.Unmarshal(assetBytes, &asset); err != nil {
		return fmt.Errorf("failed to unmarshal asset: %v", err)
	}
	if asset.OwnerID != ownerID {
		return fmt.Errorf("only asset owner can revoke access")
	}

	now, err := txTimeRFC3339(ctx)
	if err != nil {
		return err
	}

	// Resolve request by canonical requesterID OR by alias/base64/x509, scanning REQ_/REQO_ keys.
	canonRequesterID, rk, rb, err := resolveRequestForAsset(ctx, assetID, ownerID, requester)
	if err != nil {
		return err
	}

	// Revoke key even if request record is missing (edge case) as long as key exists.
	// We prefer canonical requesterID (from request) when available.
	keyID := ""
	if asset.Keys != nil {
		if canonRequesterID != "" {
			if _, ok := asset.Keys[canonRequesterID]; ok {
				keyID = canonRequesterID
			} else if k, ok := resolveUserKeyInMap(asset.Keys, canonRequesterID); ok {
				keyID = k
			}
		}
		if keyID == "" {
			// last resort: try resolve by the provided requester input
			if k, ok := resolveUserKeyInMap(asset.Keys, requester); ok {
				keyID = k
			}
		}
	}

	// If we have a request record, validate status for a real revoke.
	// Idempotency: repeated revoke should not fail.
	var req AccessRequest
	haveReq := false
	if rb != nil {
		haveReq = true
		if err := json.Unmarshal(rb, &req); err != nil {
			return fmt.Errorf("failed to unmarshal request: %v", err)
		}

		if req.Status == "PENDING" {
			return fmt.Errorf("request is PENDING; use DenyAccess instead")
		}
		// If already revoked/denied, treat as idempotent: ensure key is absent and return ok.
		if req.Status == "REVOKED" || req.Status == "DENIED" {
			if keyID != "" {
				delete(asset.Keys, keyID)
				asset.AccessLog = append(asset.AccessLog, fmt.Sprintf("[%s] ACCESS REVOKED from %s", now, keyID))
				updated, _ := json.Marshal(asset)
				_ = ctx.GetStub().PutState(assetID, updated)
			}
			return nil
		}
	}

	// If no key exists, we still allow revocation (to fix inconsistent state) only when a request exists.
	if keyID == "" {
		if haveReq {
			// Mark request as REVOKED anyway (state may be inconsistent).
			req.Status = "REVOKED"
			req.UpdatedAt = now
			if strings.TrimSpace(reason) != "" {
				req.Reason = reason
			}
			nb, _ := json.Marshal(req)
			if err := ctx.GetStub().PutState(rk, nb); err != nil {
				return fmt.Errorf("failed to update request: %v", err)
			}
			_ = s.writeAuditEvent(ctx, "ACCESS_REVOKED", assetID, ownerID, canonRequesterID, reason)
			emitEvent(ctx, "ACCESS_REVOKED", ChainEvent{
				Type:      "ACCESS_REVOKED",
				AssetID:   assetID,
				ActorID:   ownerID,
				TargetID:  canonRequesterID,
				Status:    "REVOKED",
				Timestamp: now,
				Detail:    reason,
			})
			return nil
		}
		return fmt.Errorf("request not found")
	}

	// Remove key
	delete(asset.Keys, keyID)
	asset.AccessLog = append(asset.AccessLog, fmt.Sprintf("[%s] ACCESS REVOKED from %s", now, keyID))

	updated, _ := json.Marshal(asset)
	if err := ctx.GetStub().PutState(assetID, updated); err != nil {
		return fmt.Errorf("failed to update asset: %v", err)
	}

	// Update request record if it exists
	if haveReq {
		req.Status = "REVOKED"
		req.UpdatedAt = now
		if strings.TrimSpace(reason) != "" {
			req.Reason = reason
		}
		nb, _ := json.Marshal(req)
		if err := ctx.GetStub().PutState(rk, nb); err != nil {
			return fmt.Errorf("failed to update request: %v", err)
		}
	}

	// Best-effort cleanup: remove owner pending index (should already be removed after APPROVED)
	idx, _ := reqOwnerIndexKey(ctx, asset.OwnerID, assetID, canonRequesterID)
	_ = ctx.GetStub().DelState(idx)

	// Ledger audit + chain event
	_ = s.writeAuditEvent(ctx, "ACCESS_REVOKED", assetID, ownerID, canonRequesterID, reason)

	emitEvent(ctx, "ACCESS_REVOKED", ChainEvent{
		Type:      "ACCESS_REVOKED",
		AssetID:   assetID,
		ActorID:   ownerID,
		TargetID:  canonRequesterID,
		Status:    "REVOKED",
		Timestamp: now,
		Detail:    reason,
	})

	return nil
}

// UpdateEncryptedKey allows the asset owner to update (re-wrap) the encrypted AES key for a specific user.
// This is needed when a recipient rotates their public key or a previously granted key must be refreshed.
func (s *SmartContract) UpdateEncryptedKey(ctx contractapi.TransactionContextInterface, assetID string, targetUserID string, newEncryptedKey string) error {
	assetID, _ = normalizeAssetID(assetID)
	targetUserID = strings.TrimSpace(targetUserID)
	newEncryptedKey = strings.TrimSpace(newEncryptedKey)
	if strings.TrimSpace(assetID) == "" || targetUserID == "" || newEncryptedKey == "" {
		return fmt.Errorf("assetID/targetUserID/newEncryptedKey required")
	}
	if err := validateEncryptedKey(newEncryptedKey); err != nil {
		return err
	}

	callerID, err := s.getClientID(ctx)
	if err != nil {
		return err
	}

	b, err := ctx.GetStub().GetState(assetID)
	if err != nil {
		return err
	}
	if b == nil {
		return fmt.Errorf("asset not found")
	}

	var asset Asset
	if err := json.Unmarshal(b, &asset); err != nil {
		return err
	}

	if callerID != asset.OwnerID {
		return fmt.Errorf("only owner can update encrypted keys")
	}

	if asset.Keys == nil {
		asset.Keys = map[string]string{}
	}
	asset.Keys[targetUserID] = newEncryptedKey

	nb, _ := json.Marshal(asset)
	if err := ctx.GetStub().PutState(assetID, nb); err != nil {
		return err
	}

	t, _ := txTimeRFC3339(ctx)
	emitEvent(ctx, "ENCRYPTED_KEY_UPDATED", ChainEvent{
		Type:      "ENCRYPTED_KEY_UPDATED",
		AssetID:   assetID,
		ActorID:   callerID,
		TargetID:  targetUserID,
		Status:    "OK",
		Timestamp: t,
		Detail:    "owner updated encrypted key for user",
	})

	_ = s.writeAuditEvent(ctx, "ENCRYPTED_KEY_UPDATED", assetID, callerID, targetUserID, "owner updated encrypted key")

	return nil
}

// RotateAssetContent updates the CID/FileHash and resets the per-user encrypted keys map.
// This is the on-chain part of a "real revoke": owner re-encrypts content off-chain, uploads new CID,
// then writes the new CID/hash + new key set to the ledger.
func (s *SmartContract) RotateAssetContent(
	ctx contractapi.TransactionContextInterface,
	assetID string,
	newCIDHash string,
	newFileHash string,
	newEncryptedKeyForOwner string,
	newKeysJSON string, // JSON object: {"<userID>":"<encKey>", ...} for remaining allowed users (optional)
) error {
	ownerID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return fmt.Errorf("failed to get client ID: %v", err)
	}

	isBlocked, _, _, err := s.checkBlocked(ctx, ownerID)
	if err != nil {
		return fmt.Errorf("failed to check block status: %v", err)
	}
	if isBlocked {
		return fmt.Errorf("access denied: user is blocked")
	}
	assetNorm, err := normalizeAssetID(assetID)
	if err == nil {
		assetID = assetNorm
	}

	newCIDHash = strings.TrimSpace(newCIDHash)
	newFileHash = strings.TrimSpace(newFileHash)
	newEncryptedKeyForOwner = strings.TrimSpace(newEncryptedKeyForOwner)
	newKeysJSON = strings.TrimSpace(newKeysJSON)

	if err := validateCID(newCIDHash); err != nil {
		return err
	}
	if err := validateFileHash(newFileHash); err != nil {
		return err
	}
	if err := validateEncryptedKey(newEncryptedKeyForOwner); err != nil {
		return err
	}
	if newKeysJSON != "" {
		if len(newKeysJSON) > 20000 {
			return fmt.Errorf("newKeysJSON too large")
		}
		if containsDisallowedRunes(newKeysJSON) {
			return fmt.Errorf("newKeysJSON contains disallowed characters")
		}
	}

	assetBytes, err := ctx.GetStub().GetState(assetID)
	if err != nil {
		return fmt.Errorf("failed to read asset: %v", err)
	}
	if assetBytes == nil {
		return fmt.Errorf("asset not found")
	}

	var asset Asset
	if err := json.Unmarshal(assetBytes, &asset); err != nil {
		return fmt.Errorf("failed to unmarshal asset: %v", err)
	}
	if asset.OwnerID != ownerID {
		return fmt.Errorf("only owner can rotate content")
	}

	// Build new keys map (owner always included)
	newKeys := map[string]string{
		ownerID: strings.TrimSpace(newEncryptedKeyForOwner),
	}

	if strings.TrimSpace(newKeysJSON) != "" {
		var m map[string]string
		if err := json.Unmarshal([]byte(newKeysJSON), &m); err != nil {
			return fmt.Errorf("invalid newKeysJSON: %v", err)
		}
		for k, v := range m {
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			if k == "" || v == "" {
				continue
			}
			if err := validateTextField("userID", k, 512, false); err != nil {
				continue
			}
			if err := validateEncryptedKey(v); err != nil {
				continue
			}
			newKeys[k] = v
		}
	}

	asset.CIDHash = strings.TrimSpace(newCIDHash)
	asset.FileHash = strings.TrimSpace(newFileHash)
	asset.Keys = newKeys

	ts, _ := txTimeRFC3339(ctx)
	asset.AccessLog = append(asset.AccessLog, fmt.Sprintf("[%s] CONTENT ROTATED (new CID=%s)", ts, asset.CIDHash))

	updated, _ := json.Marshal(asset)
	if err := ctx.GetStub().PutState(assetID, updated); err != nil {
		return err
	}
	// Ledger audit: CONTENT_ROTATED
	_ = s.writeAuditEvent(ctx, "CONTENT_ROTATED", assetID, ownerID, "", fmt.Sprintf("%s|%s", newCIDHash, newFileHash))

	emitEvent(ctx, "ASSET_ROTATED", ChainEvent{
		Type:      "ASSET_ROTATED",
		AssetID:   assetID,
		ActorID:   ownerID,
		Status:    "OK",
		Timestamp: ts,
		Detail:    "content rotated",
	})

	return nil
}

func (s *SmartContract) AddSuggestedCategory(ctx contractapi.TransactionContextInterface, assetID string, suggestedCategory string, confidence float64) error {
	assetNorm, err := normalizeAssetID(assetID)
	if err := requireBoundService(ctx, "MLService"); err != nil {
		return err
	}

	if err == nil {
		assetID = assetNorm
	}

	suggestedCategory = strings.TrimSpace(suggestedCategory)
	if err := validateCategory(suggestedCategory); err != nil {
		return err
	}
	if !isActionableCategory(suggestedCategory) {
		return fmt.Errorf("suggested category must be actionable")
	}
	if confidence < 0 || confidence > 100 {
		return fmt.Errorf("confidence out of bounds")
	}

	assetBytes, err := ctx.GetStub().GetState(assetID)
	if err != nil {
		return fmt.Errorf("failed to read asset: %v", err)
	}
	if assetBytes == nil {
		return fmt.Errorf("asset not found")
	}

	var asset Asset
	if err := json.Unmarshal(assetBytes, &asset); err != nil {
		return fmt.Errorf("failed to unmarshal asset: %v", err)
	}

	asset.SuggestedCategory = suggestedCategory
	asset.SuggestedConfidence = confidence
	if asset.NeedsManualReview || isManualReviewCategory(asset.Category) {
		asset.NeedsManualReview = true
	}

	updatedJSON, _ := json.Marshal(asset)
	if err := ctx.GetStub().PutState(assetID, updatedJSON); err != nil {
		return err
	}

	actor, _ := cid.GetID(ctx.GetStub())
	ts, _ := txTimeRFC3339(ctx)
	emitEvent(ctx, "ASSET_CATEGORY_SUGGESTED", ChainEvent{
		Type:      "ASSET_CATEGORY_SUGGESTED",
		AssetID:   assetID,
		ActorID:   actor,
		Timestamp: ts,
	})
	_ = s.writeAuditEvent(ctx, "ASSET_CATEGORY_SUGGESTED", assetID, actor, "", "suggested="+suggestedCategory)

	return nil
}

func (s *SmartContract) ApproveCategory(ctx contractapi.TransactionContextInterface, assetID string, approvedCategory string) error {
	ownerID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return fmt.Errorf("failed to get client ID: %v", err)
	}

	isBlocked, _, _, err := s.checkBlocked(ctx, ownerID)
	if err != nil {
		return fmt.Errorf("failed to check block status: %v", err)
	}
	if isBlocked {
		return fmt.Errorf("access denied: user is blocked")
	}
	assetNorm, err := normalizeAssetID(assetID)
	if err == nil {
		assetID = assetNorm
	}

	assetBytes, err := ctx.GetStub().GetState(assetID)
	if err != nil {
		return fmt.Errorf("failed to read asset: %v", err)
	}
	if assetBytes == nil {
		return fmt.Errorf("asset not found")
	}

	var asset Asset
	if err := json.Unmarshal(assetBytes, &asset); err != nil {
		return fmt.Errorf("failed to unmarshal asset: %v", err)
	}

	if asset.OwnerID != ownerID {
		return fmt.Errorf("only owner can approve category")
	}

	approvedCategory = strings.TrimSpace(approvedCategory)
	if err := validateCategory(approvedCategory); err != nil {
		return err
	}
	if !isActionableCategory(approvedCategory) {
		return fmt.Errorf("approved category must be a concrete category")
	}

	asset.Category = approvedCategory
	asset.ManualCategoryOverride = approvedCategory
	asset.NeedsManualReview = false

	updatedJSON, _ := json.Marshal(asset)
	if err := ctx.GetStub().PutState(assetID, updatedJSON); err != nil {
		return err
	}

	t, _ := txTimeRFC3339(ctx)
	emitEvent(ctx, "ASSET_CATEGORY_APPROVED", ChainEvent{
		Type:      "ASSET_CATEGORY_APPROVED",
		AssetID:   assetID,
		ActorID:   ownerID,
		Timestamp: t,
		Detail:    approvedCategory,
	})
	_ = s.writeAuditEvent(ctx, "ASSET_CATEGORY_APPROVED", assetID, ownerID, "", "approved="+approvedCategory)

	return nil
}

func (s *SmartContract) GetMyEncryptedKey(ctx contractapi.TransactionContextInterface, assetID string) (string, error) {
	clientID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return "", fmt.Errorf("failed to get client ID: %v", err)
	}

	// blocked users cannot fetch keys
	blocked, _, _, err := s.checkBlocked(ctx, clientID)
	if err != nil {
		return "", err
	}
	if blocked {
		return "", fmt.Errorf("access denied: user is blocked")
	}

	// user must be registered
	if _, err := s.requireUserProfile(ctx, clientID); err != nil {
		return "", err
	}

	assetNorm, err := normalizeAssetID(assetID)
	if err == nil {
		assetID = assetNorm
	}

	assetBytes, err := ctx.GetStub().GetState(assetID)
	if err != nil {
		return "", fmt.Errorf("failed to read asset: %v", err)
	}
	if assetBytes == nil {
		return "", fmt.Errorf("asset not found")
	}

	var asset Asset
	if err := json.Unmarshal(assetBytes, &asset); err != nil {
		return "", fmt.Errorf("failed to unmarshal asset: %v", err)
	}

	if asset.Keys == nil {
		return "", fmt.Errorf("no keys for asset")
	}

	enc, ok := asset.Keys[clientID]
	if !ok || strings.TrimSpace(enc) == "" {
		return "", fmt.Errorf("no access or key not found for user")
	}

	t, _ := txTimeRFC3339(ctx)
	emitEvent(ctx, "ASSET_KEY_FETCHED", ChainEvent{
		Type:      "ASSET_KEY_FETCHED",
		AssetID:   assetID,
		ActorID:   clientID,
		Timestamp: t,
	})

	return enc, nil
}

// RequestMyEncryptedKey is a transaction-safe key fetch.
// It NEVER returns an error for "denied" situations; instead it returns {status:"DENIED", message:"..."}.
// This allows the transaction to be committed and the ACCESS_DENIED event to be recorded (for risk engine / audit).
func (s *SmartContract) RequestMyEncryptedKey(ctx contractapi.TransactionContextInterface, assetID string) (map[string]string, error) {
	clientID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return nil, fmt.Errorf("failed to get client ID: %v", err)
	}

	assetNorm, err := normalizeAssetID(assetID)
	if err == nil {
		assetID = assetNorm
	}
	if strings.TrimSpace(assetID) == "" {
		t, _ := txTimeRFC3339(ctx)
		emitEvent(ctx, "ACCESS_DENIED", ChainEvent{
			Type:      "ACCESS_DENIED",
			AssetID:   assetID,
			ActorID:   clientID,
			TargetID:  clientID,
			Status:    "DENIED",
			Detail:    "BAD_ASSET_ID",
			Timestamp: t,
		})
		_ = s.writeAuditEvent(ctx, "KEY_REQUEST_DENIED", assetID, clientID, "", "denied")
		return map[string]string{"status": "DENIED", "message": "asset id must not be empty", "key": ""}, nil
	}

	// Blocked users must be denied (and we want a committed event)
	nowT, _ := txTime(ctx)
	u, _ := s.getUserProfile(ctx, clientID)
	if u != nil {
		blockedNow, _ := isBlockedAt(u, nowT)
		if blockedNow {
			t, _ := txTimeRFC3339(ctx)
			detail := "USER_BLOCKED"
			if strings.TrimSpace(u.BlockedUntil) != "" {
				detail = fmt.Sprintf("USER_BLOCKED until %s", u.BlockedUntil)
			}
			emitEvent(ctx, "ACCESS_DENIED", ChainEvent{
				Type:      "ACCESS_DENIED",
				AssetID:   assetID,
				ActorID:   clientID,
				TargetID:  clientID,
				Status:    "DENIED",
				Detail:    detail,
				Reason:    u.BlockReason,
				Timestamp: t,
			})
			_ = s.writeAuditEvent(ctx, "KEY_REQUEST_DENIED", assetID, clientID, "", "USER_BLOCKED")
			return map[string]string{"status": "DENIED", "message": "access denied: user is blocked", "key": ""}, nil
		}
	}

	assetBytes, err := ctx.GetStub().GetState(assetID)
	if err != nil {
		return nil, fmt.Errorf("failed to read asset: %v", err)
	}
	if assetBytes == nil {
		t, _ := txTimeRFC3339(ctx)
		emitEvent(ctx, "ACCESS_DENIED", ChainEvent{
			Type:      "ACCESS_DENIED",
			AssetID:   assetID,
			ActorID:   clientID,
			TargetID:  clientID,
			Status:    "DENIED",
			Detail:    "ASSET_NOT_FOUND",
			Timestamp: t,
		})
		_ = s.writeAuditEvent(ctx, "KEY_REQUEST_DENIED", assetID, clientID, "", "ASSET_NOT_FOUND")
		return map[string]string{"status": "DENIED", "message": "asset not found", "key": ""}, nil
	}

	var asset Asset
	if err := json.Unmarshal(assetBytes, &asset); err != nil {
		return nil, fmt.Errorf("failed to unmarshal asset: %v", err)
	}
	if asset.Keys == nil {
		t, _ := txTimeRFC3339(ctx)
		emitEvent(ctx, "ACCESS_DENIED", ChainEvent{
			Type:      "ACCESS_DENIED",
			AssetID:   assetID,
			ActorID:   clientID,
			TargetID:  clientID,
			Status:    "DENIED",
			Detail:    "NO_KEYS",
			Timestamp: t,
		})
		_ = s.writeAuditEvent(ctx, "KEY_REQUEST_DENIED", assetID, clientID, "", "NO_KEYS")
		return map[string]string{"status": "DENIED", "message": "no keys for asset", "key": ""}, nil
	}

	enc, ok := asset.Keys[clientID]
	if !ok || strings.TrimSpace(enc) == "" {
		t, _ := txTimeRFC3339(ctx)
		emitEvent(ctx, "ACCESS_DENIED", ChainEvent{
			Type:      "ACCESS_DENIED",
			AssetID:   assetID,
			ActorID:   clientID,
			TargetID:  clientID,
			Status:    "DENIED",
			Detail:    "NO_ACCESS_OR_KEY",
			Timestamp: t,
		})
		_ = s.writeAuditEvent(ctx, "KEY_REQUEST_DENIED", assetID, clientID, "", "NO_ACCESS_OR_KEY")
		return map[string]string{"status": "DENIED", "message": "no access or key not found for user", "key": ""}, nil
	}

	// success
	t, _ := txTimeRFC3339(ctx)
	emitEvent(ctx, "ASSET_KEY_FETCHED", ChainEvent{
		Type:      "ASSET_KEY_FETCHED",
		AssetID:   assetID,
		ActorID:   clientID,
		TargetID:  clientID,
		Status:    "OK",
		Timestamp: t,
	})

	_ = s.writeAuditEvent(ctx, "KEY_REQUEST_OK", assetID, clientID, "", "key returned")
	return map[string]string{"status": "OK", "message": "ok", "key": enc}, nil
}

// LogDownload records a successful download attempt into the asset audit trail.
// Requirement: caller must be the owner OR have a stored encrypted key in asset.Keys[callerID].
// Also enforces "blocked user cannot download" policy.
func (s *SmartContract) LogDownload(ctx contractapi.TransactionContextInterface, assetID string) error {
	clientID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return fmt.Errorf("failed to get client ID: %v", err)
	}

	// blocked users cannot log downloads
	blocked, _, _, err := s.checkBlocked(ctx, clientID)
	if err != nil {
		return err
	}
	if blocked {
		return fmt.Errorf("access denied: user is blocked")
	}

	// user must be registered
	if _, err := s.requireUserProfile(ctx, clientID); err != nil {
		return err
	}

	normID, err := normalizeAssetID(assetID)
	if err == nil {
		assetID = normID
	}

	assetBytes, err := ctx.GetStub().GetState(assetID)
	if err != nil {
		return fmt.Errorf("failed to read asset: %v", err)
	}
	if assetBytes == nil {
		return fmt.Errorf("asset %s does not exist", assetID)
	}

	var asset Asset
	if err := json.Unmarshal(assetBytes, &asset); err != nil {
		return fmt.Errorf("failed to unmarshal asset: %v", err)
	}

	// Allow if owner OR has key entry
	if asset.OwnerID != clientID {
		if asset.Keys == nil {
			return fmt.Errorf("access denied: no key for caller")
		}
		if _, ok := asset.Keys[clientID]; !ok {
			return fmt.Errorf("access denied: no key for caller")
		}
	}

	ts, _ := txTimeRFC3339(ctx)
	asset.AccessLog = append(asset.AccessLog, fmt.Sprintf("[%s] DOWNLOAD by %s", ts, clientID))

	// Persist
	b, _ := json.Marshal(asset)
	if err := ctx.GetStub().PutState(assetID, b); err != nil {
		return fmt.Errorf("failed to update asset: %v", err)
	}

	// Persist download audit records for query/reporting
	if err := s.writeDownloadAudit(ctx, assetID, clientID, ts); err != nil {
		return fmt.Errorf("failed to write download audit: %v", err)
	}

	emitEvent(ctx, "ASSET_DOWNLOADED", ChainEvent{
		Type:      "DOWNLOAD",
		AssetID:   assetID,
		ActorID:   clientID,
		Status:    "OK",
		Timestamp: ts,
	})
	_ = s.writeAuditEvent(ctx, "DOWNLOAD_LOGGED", assetID, clientID, "", "download logged")

	return nil
}

// getClientID returns the Fabric client ID for the proposal creator (base64-encoded identity string).
func (s *SmartContract) getClientID(ctx contractapi.TransactionContextInterface) (string, error) {
	return cid.GetID(ctx.GetStub())
}

// isSecurityService checks whether the caller has the "SecurityService" role attribute.
func (s *SmartContract) isSecurityService(ctx contractapi.TransactionContextInterface) bool {
	return requireRole(ctx, "SecurityService") == nil
}

// readAssetRaw loads the full Asset object from state WITHOUT access filtering.
func (s *SmartContract) readAssetRaw(ctx contractapi.TransactionContextInterface, assetID string) (*Asset, error) {
	if assetID == "" {
		return nil, fmt.Errorf("asset id must not be empty")
	}
	b, err := ctx.GetStub().GetState(assetID)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, fmt.Errorf("asset not found")
	}
	var a Asset
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// writeDownloadAudit persists download audit records under two composite-key indexes:
// 1) by asset:  dlA~assetID~timestamp~txID
// 2) by user:   dlU~actorID~timestamp~txID~assetID
func (s *SmartContract) writeDownloadAudit(ctx contractapi.TransactionContextInterface, assetID, actorID, timestamp string) error {
	txID := ctx.GetStub().GetTxID()
	rec := &DownloadAudit{
		DocType:   "DOWNLOAD_AUDIT",
		AssetID:   assetID,
		ActorID:   actorID,
		Timestamp: timestamp,
		TxID:      txID,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	kAsset, err := ctx.GetStub().CreateCompositeKey(downloadAuditByAssetIndex, []string{assetID, timestamp, txID})
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(kAsset, b); err != nil {
		return err
	}

	kUser, err := ctx.GetStub().CreateCompositeKey(downloadAuditByUserIndex, []string{actorID, timestamp, txID, assetID})
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(kUser, b)
}

func normalizeAuditAssetID(assetID string) string {
	if strings.TrimSpace(assetID) == "" {
		return "NOASSET"
	}
	return assetID
}

// writeAuditEvent persists an immutable audit event under three composite-key indexes:
// 1) by asset: auA~assetID~timestamp~txID~eventType
// 2) by user (actor): auU~actorID~timestamp~txID~eventType~assetID
// 3) by type: auT~eventType~timestamp~txID~assetID
func (s *SmartContract) writeAuditEvent(ctx contractapi.TransactionContextInterface, eventType, assetID, actorID, targetUserID, detail string) error {
	ts, _ := txTimeRFC3339(ctx)
	txID := ctx.GetStub().GetTxID()

	assetID = normalizeAuditAssetID(assetID)

	rec := &AuditEvent{
		DocType:      "AUDIT_EVENT",
		EventType:    eventType,
		AssetID:      assetID,
		ActorID:      actorID,
		TargetUserID: targetUserID,
		Timestamp:    ts,
		TxID:         txID,
		Detail:       detail,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	kAsset, err := ctx.GetStub().CreateCompositeKey(auditByAssetIndex, []string{assetID, ts, txID, eventType})
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(kAsset, b); err != nil {
		return err
	}

	kUser, err := ctx.GetStub().CreateCompositeKey(auditByUserIndex, []string{actorID, ts, txID, eventType, assetID})
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(kUser, b); err != nil {
		return err
	}

	// Optional index: by target user (who was affected by the action)
	if strings.TrimSpace(targetUserID) != "" {
		kTarget, err := ctx.GetStub().CreateCompositeKey(auditByTargetUserIndex, []string{targetUserID, ts, txID, eventType, assetID})
		if err != nil {
			return err
		}
		if err := ctx.GetStub().PutState(kTarget, b); err != nil {
			return err
		}
	}

	kType, err := ctx.GetStub().CreateCompositeKey(auditByTypeIndex, []string{eventType, ts, txID, assetID})
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(kType, b)
}

// QueryAuditEventsByAsset returns audit events for a specific asset.
// Authorization: SecurityService OR asset owner.
func (s *SmartContract) QueryAuditEventsByAsset(ctx contractapi.TransactionContextInterface, assetID string) (*AuditEventQueryResult, error) {
	callerID, err := s.getClientID(ctx)
	if err != nil {
		return nil, err
	}

	assetID, _ = normalizeAssetID(assetID)
	if !s.isSecurityService(ctx) {
		a, err := s.readAssetRaw(ctx, assetID)
		if err != nil {
			return nil, err
		}
		if a.OwnerID != callerID {
			return nil, fmt.Errorf("access denied: only SecurityService or asset owner can query audits")
		}
	}

	it, err := ctx.GetStub().GetStateByPartialCompositeKey(auditByAssetIndex, []string{assetID})
	if err != nil {
		return nil, err
	}
	defer it.Close()

	out := &AuditEventQueryResult{Items: []*AuditEvent{}}
	for it.HasNext() {
		kv, err := it.Next()
		if err != nil {
			return nil, err
		}
		var rec AuditEvent
		if err := json.Unmarshal(kv.Value, &rec); err == nil {
			recCopy := rec
			out.Items = append(out.Items, &recCopy)
		}
	}
	return out, nil
}

// QueryAuditEventsByUser returns audit events created by a given actor.
// Authorization: SecurityService OR the same user.
func (s *SmartContract) QueryAuditEventsByUser(ctx contractapi.TransactionContextInterface, actorID string) (*AuditEventQueryResult, error) {
	callerID, err := s.getClientID(ctx)
	if err != nil {
		return nil, err
	}
	if !s.isSecurityService(ctx) && callerID != actorID {
		return nil, fmt.Errorf("access denied: only SecurityService or the same user can query audits")
	}

	it, err := ctx.GetStub().GetStateByPartialCompositeKey(auditByUserIndex, []string{actorID})
	if err != nil {
		return nil, err
	}
	defer it.Close()

	out := &AuditEventQueryResult{Items: []*AuditEvent{}}
	for it.HasNext() {
		kv, err := it.Next()
		if err != nil {
			return nil, err
		}
		var rec AuditEvent
		if err := json.Unmarshal(kv.Value, &rec); err == nil {
			recCopy := rec
			out.Items = append(out.Items, &recCopy)
		}
	}
	return out, nil
}

// QueryAuditEventsByTargetUser returns audit events where the given user is the *target* (affected user).
// Authorization: SecurityService or the target user themselves.
func (s *SmartContract) QueryAuditEventsByTargetUser(ctx contractapi.TransactionContextInterface, targetUserID string) (*AuditEventQueryResult, error) {
	callerID, err := s.getClientID(ctx)
	if err != nil {
		return nil, err
	}
	if !s.isSecurityService(ctx) && callerID != targetUserID {
		return nil, fmt.Errorf("access denied: only SecurityService or the target user can query these audits")
	}

	it, err := ctx.GetStub().GetStateByPartialCompositeKey(auditByTargetUserIndex, []string{targetUserID})
	if err != nil {
		return nil, err
	}
	defer it.Close()

	out := &AuditEventQueryResult{Items: []*AuditEvent{}}
	for it.HasNext() {
		kv, err := it.Next()
		if err != nil {
			return nil, err
		}
		if kv == nil || len(kv.Value) == 0 {
			continue
		}
		var rec AuditEvent
		if err := json.Unmarshal(kv.Value, &rec); err != nil {
			continue
		}
		recCopy := rec
		out.Items = append(out.Items, &recCopy)
	}
	return out, nil
}

// QueryAuditEventsByType returns audit events of a given type.
// Authorization: SecurityService only.
func (s *SmartContract) QueryAuditEventsByType(ctx contractapi.TransactionContextInterface, eventType string) (*AuditEventQueryResult, error) {
	if !s.isSecurityService(ctx) {
		return nil, fmt.Errorf("access denied: only SecurityService can query audits by type")
	}

	it, err := ctx.GetStub().GetStateByPartialCompositeKey(auditByTypeIndex, []string{eventType})
	if err != nil {
		return nil, err
	}
	defer it.Close()

	out := &AuditEventQueryResult{Items: []*AuditEvent{}}
	for it.HasNext() {
		kv, err := it.Next()
		if err != nil {
			return nil, err
		}
		var rec AuditEvent
		if err := json.Unmarshal(kv.Value, &rec); err == nil {
			recCopy := rec
			out.Items = append(out.Items, &recCopy)
		}
	}
	return out, nil
}

// QueryDownloadAuditsByAsset returns download audit records for a specific asset.
// Authorization: SecurityService OR asset owner.
func (s *SmartContract) QueryDownloadAuditsByAsset(ctx contractapi.TransactionContextInterface, assetID string) (*DownloadAuditQueryResult, error) {
	callerID, err := s.getClientID(ctx)
	if err != nil {
		return nil, err
	}

	assetID, _ = normalizeAssetID(assetID)

	if !s.isSecurityService(ctx) {
		a, err := s.readAssetRaw(ctx, assetID)
		if err != nil {
			return nil, err
		}
		if a.OwnerID != callerID {
			return nil, fmt.Errorf("access denied")
		}
	}

	iter, err := ctx.GetStub().GetStateByPartialCompositeKey(downloadAuditByAssetIndex, []string{assetID})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	// IMPORTANT: do NOT return a nil slice.
	// A nil slice marshals to JSON null, but the Contract API metadata schema
	// for DownloadAuditQueryResult.Items expects an array, so returning null
	// triggers "Value did not match schema" and the peer returns 500.
	out := make([]*DownloadAudit, 0)
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var rec DownloadAudit
		if err := json.Unmarshal(kv.Value, &rec); err != nil {
			return nil, err
		}
		out = append(out, &rec)
	}
	return &DownloadAuditQueryResult{Items: out}, nil
}

// QueryDownloadAuditsByUser returns download audit records for a specific user.
// Authorization: SecurityService OR the same user (caller == userID).
func (s *SmartContract) QueryDownloadAuditsByUser(ctx contractapi.TransactionContextInterface, userID string) (*DownloadAuditQueryResult, error) {
	callerID, err := s.getClientID(ctx)
	if err != nil {
		return nil, err
	}
	if !s.isSecurityService(ctx) && callerID != userID {
		return nil, fmt.Errorf("access denied")
	}

	iter, err := ctx.GetStub().GetStateByPartialCompositeKey(downloadAuditByUserIndex, []string{userID})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	// See note in QueryDownloadAuditsByAsset: never return a nil slice.
	out := make([]*DownloadAudit, 0)
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var rec DownloadAudit
		if err := json.Unmarshal(kv.Value, &rec); err != nil {
			return nil, err
		}
		out = append(out, &rec)
	}
	return &DownloadAuditQueryResult{Items: out}, nil
}

func (s *SmartContract) WhoAmI(ctx contractapi.TransactionContextInterface) (map[string]string, error) {
	id, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return nil, err
	}
	msp, _ := cid.GetMSPID(ctx.GetStub())

	role, foundRole, _ := cid.GetAttributeValue(ctx.GetStub(), "role")
	dept, foundDept, _ := cid.GetAttributeValue(ctx.GetStub(), "department")

	out := map[string]string{
		"clientID": id,
		"mspID":    msp,
	}
	if foundRole {
		out["role"] = role
	} else {
		out["role"] = ""
	}
	if foundDept {
		out["department"] = dept
	} else {
		out["department"] = ""
	}
	return out, nil
}

func (s *SmartContract) BindServiceIdentity(ctx contractapi.TransactionContextInterface, service string, clientID string) error {
	// можно оставить SecurityService, либо временно Admin/OrgAdmin — но лучше SecurityService
	if err := requireRole(ctx, "SecurityService"); err != nil {
		return err
	}
	service = strings.TrimSpace(service)
	clientID = strings.TrimSpace(clientID)
	if service == "" || clientID == "" {
		return fmt.Errorf("service and clientID must not be empty")
	}
	return ctx.GetStub().PutState(serviceBindingKey(service), []byte(clientID))
}

func (s *SmartContract) GetServiceBinding(ctx contractapi.TransactionContextInterface, service string) (map[string]string, error) {
	service = strings.TrimSpace(service)
	if err := validateTextField("service", service, 128, false); err != nil {
		return nil, err
	}
	bound, err := ctx.GetStub().GetState(serviceBindingKey(service))
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"service":  service,
		"clientID": strings.TrimSpace(string(bound)),
	}, nil
}

func requireBoundService(ctx contractapi.TransactionContextInterface, service string) error {
	callerID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return err
	}
	bound, err := ctx.GetStub().GetState(serviceBindingKey(service))
	if err != nil {
		return err
	}
	if bound == nil || strings.TrimSpace(string(bound)) == "" {
		return fmt.Errorf("service %s is not bound to any identity", service)
	}
	if callerID != string(bound) {
		return fmt.Errorf("access denied: caller is not bound for service=%s", service)
	}
	return nil
}

func (s *SmartContract) GetUserPublicKey(ctx contractapi.TransactionContextInterface, userID string) (string, error) {
	if strings.TrimSpace(userID) == "" {
		return "", fmt.Errorf("userID is empty")
	}
	u, err := s.getUserProfile(ctx, userID)
	if err != nil {
		return "", err
	}
	if u == nil || strings.TrimSpace(u.PublicKey) == "" {
		return "", fmt.Errorf("public key not found")
	}
	return u.PublicKey, nil
}

// =====================
// Main
// =====================

func main() {
	cc, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		log.Panicf("Error creating chaincode: %v", err)
	}

	if err := cc.Start(); err != nil {
		log.Panicf("Error starting chaincode: %v", err)
	}
}

func (s *SmartContract) GetPendingRequests(ctx contractapi.TransactionContextInterface) ([]*AccessRequest, error) {
	ownerID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return nil, fmt.Errorf("failed to get owner id: %v", err)
	}

	// We store owner index keys as plain strings:
	//   REQO_<ownerID>_<assetID>_<requesterID>
	// assetID may contain '_' so we split from the right (last underscore).
	prefix := "REQO_" + ownerID + "_"
	startKey := prefix
	endKey := prefix + string(rune(0x10FFFF))

	it, err := ctx.GetStub().GetStateByRange(startKey, endKey)
	if err != nil {
		return nil, err
	}
	defer it.Close()

	var out []*AccessRequest
	for it.HasNext() {
		kv, err := it.Next()
		if err != nil {
			return nil, err
		}
		idxKey := kv.Key
		rest := strings.TrimPrefix(idxKey, prefix)
		if rest == idxKey { // not our prefix
			continue
		}
		last := strings.LastIndex(rest, "_")
		if last <= 0 || last >= len(rest)-1 {
			continue
		}
		assetID := rest[:last]
		requesterID := rest[last+1:]

		reqK, _ := reqKey(ctx, assetID, requesterID)
		b, err := ctx.GetStub().GetState(reqK)
		if err != nil {
			return nil, err
		}
		if len(b) == 0 {
			// index exists, but request was deleted; cleanup index best-effort
			_ = ctx.GetStub().DelState(idxKey)
			continue
		}

		var req AccessRequest
		if err := json.Unmarshal(b, &req); err != nil {
			return nil, err
		}

		// only pending
		if strings.ToUpper(strings.TrimSpace(req.Status)) != "PENDING" {
			continue
		}

		// Ensure required fields (backward compatible with older stored requests)
		if strings.TrimSpace(req.Department) == "" {
			req.Department = "UNKNOWN"
		}
		if strings.TrimSpace(req.AssetCategory) == "" {
			// try to fill from asset (owner can read full asset)
			asset, err := s.ReadAsset(ctx, assetID)
			if err == nil && asset != nil {
				req.AssetCategory = strings.TrimSpace(asset.Category)
			}
			if strings.TrimSpace(req.AssetCategory) == "" {
				req.AssetCategory = "UNKNOWN"
			}
		}
		if strings.TrimSpace(req.AssetID) == "" {
			req.AssetID = assetID
		}
		if strings.TrimSpace(req.RequesterID) == "" {
			req.RequesterID = requesterID
		}

		out = append(out, &req)
	}

	return out, nil
}

// isNotFoundErr returns true when the chaincode wants to treat an error as "missing asset".
// We intentionally convert this into a DENIED result (not a 500 error) for better UX and better monitoring.
func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	es := strings.ToLower(strings.TrimSpace(err.Error()))
	if es == "" {
		return false
	}
	// current code paths use "asset not found"
	if strings.Contains(es, "asset not found") {
		return true
	}
	// be tolerant to slightly different wording
	if strings.Contains(es, "not found") && strings.Contains(es, "asset") {
		return true
	}
	return false
}

// GetMyRequests returns all access requests created by the caller (requester).
// Requests are stored under keys: REQ_<assetID>_<requesterID>.
// For large ledgers, consider adding a requester composite-key index to avoid scanning the full keyspace.
func (s *SmartContract) GetMyRequests(ctx contractapi.TransactionContextInterface) ([]*AccessRequest, error) {
	callerID, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return nil, fmt.Errorf("failed to get caller id: %v", err)
	}

	results := make([]*AccessRequest, 0)

	it, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer it.Close()

	for it.HasNext() {
		kv, err := it.Next()
		if err != nil {
			return nil, err
		}
		// Request records use the prefix "REQ_" (owner index uses "REQO_").
		if !strings.HasPrefix(kv.Key, "REQ_") {
			continue
		}

		var req AccessRequest
		if err := json.Unmarshal(kv.Value, &req); err != nil {
			// Skip malformed entries instead of failing the whole query
			continue
		}
		if req.RequesterID != callerID {
			continue
		}
		r := req
		results = append(results, &r)
	}

	return results, nil
}
