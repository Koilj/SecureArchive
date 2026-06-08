package main

import (
	"encoding/base64"
	"testing"
)

func TestValidateEncryptedKeyRejectsMalformedV2Envelope(t *testing.T) {
	if err := validateEncryptedKey("plain-legacy-key"); err != nil {
		t.Fatalf("legacy key should remain accepted: %v", err)
	}

	bad := keyEnvelopeV2Prefix + base64.StdEncoding.EncodeToString([]byte(`{"type":"wrong","version":2}`))
	if err := validateEncryptedKey(bad); err == nil {
		t.Fatal("malformed v2 envelope should be rejected")
	}

	if err := validateEncryptedKey(""); err == nil {
		t.Fatal("empty encrypted key should be rejected")
	}
}

func TestPolicyAllowsDepartment(t *testing.T) {
	if !policyAllowsDepartment("IT Department", "Cryptography and Security") {
		t.Fatal("IT department should be allowed for security category")
	}
	if policyAllowsDepartment("Biology", "Cryptography and Security") {
		t.Fatal("biology department should not be allowed for security category")
	}
	if !policyAllowsDepartment("Physics", "Unverified") {
		t.Fatal("manual-review categories should not be auto-denied")
	}
	if policyAllowsDepartment("Physics", "Restricted") {
		t.Fatal("restricted category should be allowed only for IT by default")
	}
}

func TestValidateCategoryRejectsUnsafeValues(t *testing.T) {
	if err := validateCategory("Machine Learning"); err != nil {
		t.Fatalf("valid category rejected: %v", err)
	}
	if err := validateCategory("<script>"); err == nil {
		t.Fatal("script-like category should be rejected")
	}
	if err := validateCategory(""); err == nil {
		t.Fatal("empty category should be rejected")
	}
}
