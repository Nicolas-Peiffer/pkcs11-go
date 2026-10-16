// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import (
	"errors"
	"testing"
)

// TestRejectWeakMechanismsRejectsKnownWeak checks that every mechanism in the
// weak set is refused and that a strong mechanism is allowed.
func TestRejectWeakMechanismsRejectsKnownWeak(t *testing.T) {
	weak := []uint{
		CKM_MD5,
		CKM_SHA_1,
		CKM_SHA1_RSA_PKCS,
		CKM_DES_CBC,
		CKM_RC4,
		CKM_SSL3_SHA1_MAC,
		CKM_PBE_SHA1_RC4_128,
	}
	for _, m := range weak {
		if err := RejectWeakMechanisms(m); err == nil {
			t.Errorf("RejectWeakMechanisms(%#x) = nil, want error", m)
		}
	}

	strong := []uint{
		CKM_SHA256,
		CKM_SHA256_RSA_PKCS,
		CKM_AES_CBC,
		CKM_AES_GCM,
		CKM_ECDSA,
	}
	for _, m := range strong {
		if err := RejectWeakMechanisms(m); err != nil {
			t.Errorf("RejectWeakMechanisms(%#x) = %v, want nil", m, err)
		}
	}
}

// TestSetMechanismPolicyNilAllowsAll checks that the default (nil) policy
// permits every mechanism, including weak ones.
func TestSetMechanismPolicyNilAllowsAll(t *testing.T) {
	SetMechanismPolicy(nil)
	t.Cleanup(func() { SetMechanismPolicy(nil) })

	if err := checkMechanism(CKM_MD5); err != nil {
		t.Errorf("checkMechanism(MD5) with nil policy = %v, want nil", err)
	}
}

// TestSetMechanismPolicyInstalled checks that an installed policy is consulted
// by checkMechanism and can be removed again.
func TestSetMechanismPolicyInstalled(t *testing.T) {
	SetMechanismPolicy(MechanismPolicyFunc(RejectWeakMechanisms))
	t.Cleanup(func() { SetMechanismPolicy(nil) })

	if err := checkMechanism(CKM_MD5); err == nil {
		t.Error("checkMechanism(MD5) with RejectWeakMechanisms = nil, want error")
	}
	if err := checkMechanism(CKM_AES_GCM); err != nil {
		t.Errorf("checkMechanism(AES_GCM) with RejectWeakMechanisms = %v, want nil", err)
	}

	SetMechanismPolicy(nil)
	if err := checkMechanism(CKM_MD5); err != nil {
		t.Errorf("checkMechanism(MD5) after removing policy = %v, want nil", err)
	}
}

// TestNewMechanismPanicsOnPolicyViolation checks that a rejected mechanism
// panics at construction time.
func TestNewMechanismPanicsOnPolicyViolation(t *testing.T) {
	SetMechanismPolicy(MechanismPolicyFunc(RejectWeakMechanisms))
	t.Cleanup(func() { SetMechanismPolicy(nil) })

	defer func() {
		if r := recover(); r == nil {
			t.Error("NewMechanism(MD5) did not panic under RejectWeakMechanisms")
		}
	}()
	_ = NewMechanism(CKM_MD5, nil)
}

// TestNewMechanismWithParamsPanicsOnPolicyViolation checks the params
// constructor enforces the policy too.
func TestNewMechanismWithParamsPanicsOnPolicyViolation(t *testing.T) {
	SetMechanismPolicy(MechanismPolicyFunc(RejectWeakMechanisms))
	t.Cleanup(func() { SetMechanismPolicy(nil) })

	defer func() {
		if r := recover(); r == nil {
			t.Error("NewMechanismWithParams(MD5) did not panic under RejectWeakMechanisms")
		}
	}()
	_ = NewMechanismWithParams(CKM_MD5, nil)
}

// TestNewMechanismAllowsStrongUnderPolicy checks a strong mechanism still
// constructs when the policy is installed.
func TestNewMechanismAllowsStrongUnderPolicy(t *testing.T) {
	SetMechanismPolicy(MechanismPolicyFunc(RejectWeakMechanisms))
	t.Cleanup(func() { SetMechanismPolicy(nil) })

	m := NewMechanism(CKM_AES_GCM, nil)
	if m == nil || m.Mechanism != CKM_AES_GCM {
		t.Fatalf("NewMechanism(AES_GCM) = %+v, want mechanism %#x", m, CKM_AES_GCM)
	}
}

// TestMechanismPolicyFuncError checks the adapter forwards the error verbatim.
func TestMechanismPolicyFuncError(t *testing.T) {
	sentinel := errors.New("nope")
	p := MechanismPolicyFunc(func(uint) error { return sentinel })
	if err := p.Allow(CKM_AES_GCM); !errors.Is(err, sentinel) {
		t.Errorf("Allow = %v, want %v", err, sentinel)
	}
}

// TestCMechanismEnforcesPolicyOnLiteral checks that a Mechanism built as a
// struct literal, which skips the constructors, is still rejected when it is
// marshalled for an operation.
func TestCMechanismEnforcesPolicyOnLiteral(t *testing.T) {
	SetMechanismPolicy(MechanismPolicyFunc(RejectWeakMechanisms))
	t.Cleanup(func() { SetMechanismPolicy(nil) })

	mech, freeMech, err := cMechanism(&Mechanism{Mechanism: CKM_MD5})
	if err == nil {
		freeMech()
		t.Fatal("cMechanism(&Mechanism{MD5}) = nil error under RejectWeakMechanisms")
	}
	if mech != nil {
		t.Errorf("cMechanism returned a mechanism alongside the policy error")
	}
}

// TestCMechanismAllowsStrongUnderPolicy checks a strong mechanism still
// marshals when the policy is installed.
func TestCMechanismAllowsStrongUnderPolicy(t *testing.T) {
	SetMechanismPolicy(MechanismPolicyFunc(RejectWeakMechanisms))
	t.Cleanup(func() { SetMechanismPolicy(nil) })

	mech, freeMech, err := cMechanism(&Mechanism{Mechanism: CKM_AES_CBC_PAD, Parameter: make([]byte, 16)})
	if err != nil {
		t.Fatalf("cMechanism(AES_CBC_PAD) = %v, want nil", err)
	}
	defer freeMech()
	if mech == nil {
		t.Fatal("cMechanism(AES_CBC_PAD) returned a nil mechanism")
	}
}

// TestPolicyChecksParameterHashes checks that the digests named inside a
// structured parameter are judged by the policy, so a strong outer mechanism
// cannot carry a weak hash, MGF or KDF.
func TestPolicyChecksParameterHashes(t *testing.T) {
	SetMechanismPolicy(MechanismPolicyFunc(RejectWeakMechanisms))
	t.Cleanup(func() { SetMechanismPolicy(nil) })

	weak := map[string]*Mechanism{
		"OAEP hash SHA-1":  {Mechanism: CKM_RSA_PKCS_OAEP, params: NewOAEPParams(CKM_SHA_1, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, nil)},
		"OAEP MGF1-SHA1":   {Mechanism: CKM_RSA_PKCS_OAEP, params: NewOAEPParams(CKM_SHA256, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, nil)},
		"PSS hash SHA-1":   {Mechanism: CKM_RSA_PKCS_PSS, params: NewPSSParams(CKM_SHA_1, CKG_MGF1_SHA256, 32)},
		"PSS MGF1-SHA1":    {Mechanism: CKM_RSA_PKCS_PSS, params: NewPSSParams(CKM_SHA256, CKG_MGF1_SHA1, 32)},
		"ECDH1 SHA-1 KDF":  {Mechanism: CKM_ECDH1_DERIVE, params: NewECDH1DeriveParams(CKD_SHA1_KDF, nil, []byte{4})},
		"ECDH1 SP800 SHA1": {Mechanism: CKM_ECDH1_DERIVE, params: NewECDH1DeriveParams(CKD_SHA1_KDF_SP800, nil, []byte{4})},
	}
	for name, m := range weak {
		if err := checkMechanismUse(m); err == nil {
			t.Errorf("%s: checkMechanismUse = nil, want policy error", name)
		}
	}

	strong := map[string]*Mechanism{
		"OAEP SHA-256":    {Mechanism: CKM_RSA_PKCS_OAEP, params: NewOAEPParams(CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, nil)},
		"PSS SHA-384":     {Mechanism: CKM_RSA_PKCS_PSS, params: NewPSSParams(CKM_SHA384, CKG_MGF1_SHA384, 48)},
		"ECDH1 CKD_NULL":  {Mechanism: CKM_ECDH1_DERIVE, params: NewECDH1DeriveParams(CKD_NULL, nil, []byte{4})},
		"ECDH1 SHA-256":   {Mechanism: CKM_ECDH1_DERIVE, params: NewECDH1DeriveParams(CKD_SHA256_KDF, nil, []byte{4})},
		"GCM (no hashes)": {Mechanism: CKM_AES_GCM, params: nil},
	}
	for name, m := range strong {
		if err := checkMechanismUse(m); err != nil {
			t.Errorf("%s: checkMechanismUse = %v, want nil", name, err)
		}
	}

	defer func() {
		if r := recover(); r == nil {
			t.Error("NewMechanismWithParams(OAEP, SHA-1) did not panic under RejectWeakMechanisms")
		}
	}()
	_ = NewMechanismWithParams(CKM_RSA_PKCS_OAEP, NewOAEPParams(CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, nil))
}
