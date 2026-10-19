// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// TestIntegrationEmptyInput checks that the data-taking calls accept a
// zero-length input. An empty message is legitimate for every one of them: the
// digest or signature of "", AES-GCM authenticating associated data only, a
// multi-part operation fed an empty chunk. Each subtest uses its own session,
// so a module that rejects the input and leaves the operation active cannot
// spill into the next one.
func TestIntegrationEmptyInput(t *testing.T) {
	wantDigest := sha256.Sum256(nil)

	t.Run("Digest", func(t *testing.T) {
		sh := requireSession(t)
		if err := testCtx.DigestInit(sh, NewMechanism(CKM_SHA256, nil)); err != nil {
			t.Fatalf("DigestInit: %v", err)
		}
		got, err := testCtx.Digest(sh, nil)
		if err != nil {
			t.Fatalf("Digest(empty): %v", err)
		}
		if !bytes.Equal(got, wantDigest[:]) {
			t.Fatalf("Digest(empty) = %x, want %x", got, wantDigest)
		}
	})

	t.Run("DigestUpdate", func(t *testing.T) {
		sh := requireSession(t)
		if err := testCtx.DigestInit(sh, NewMechanism(CKM_SHA256, nil)); err != nil {
			t.Fatalf("DigestInit: %v", err)
		}
		if err := testCtx.DigestUpdate(sh, nil); err != nil {
			t.Fatalf("DigestUpdate(empty): %v", err)
		}
		got, err := testCtx.DigestFinal(sh)
		if err != nil {
			t.Fatalf("DigestFinal: %v", err)
		}
		if !bytes.Equal(got, wantDigest[:]) {
			t.Fatalf("multi-part digest of empty input = %x, want %x", got, wantDigest)
		}
	})

	t.Run("EncryptDecryptGCM", func(t *testing.T) {
		sh := requireSession(t)
		key, err := genAESKeyRaw(t, sh, "empty-input-gcm")
		if err != nil {
			t.Fatalf("GenerateKey(AES): %v", err)
		}
		iv := bytes.Repeat([]byte{0x24}, 12)
		aad := []byte("authenticated, not encrypted")

		params := NewGCMParams(iv, aad, 128)
		defer params.Free()
		if err := testCtx.EncryptInit(sh, NewMechanismWithParams(CKM_AES_GCM, params), key); err != nil {
			t.Fatalf("EncryptInit: %v", err)
		}
		tag, err := testCtx.Encrypt(sh, nil)
		if err != nil {
			t.Fatalf("Encrypt(empty): %v", err)
		}
		if len(tag) != 16 {
			t.Fatalf("Encrypt(empty) returned %d bytes, want the 16-byte tag", len(tag))
		}

		dparams := NewGCMParams(iv, aad, 128)
		defer dparams.Free()
		if err := testCtx.DecryptInit(sh, NewMechanismWithParams(CKM_AES_GCM, dparams), key); err != nil {
			t.Fatalf("DecryptInit: %v", err)
		}
		pt, err := testCtx.Decrypt(sh, tag)
		if err != nil {
			t.Fatalf("Decrypt(tag only): %v", err)
		}
		if len(pt) != 0 {
			t.Fatalf("Decrypt(tag only) = %x, want empty", pt)
		}
	})

	t.Run("EncryptUpdateCBC", func(t *testing.T) {
		sh := requireSession(t)
		key, err := genAESKeyRaw(t, sh, "empty-input-cbc")
		if err != nil {
			t.Fatalf("GenerateKey(AES): %v", err)
		}
		iv := make([]byte, 16)
		if err := testCtx.EncryptInit(sh, NewMechanism(CKM_AES_CBC, iv), key); err != nil {
			t.Fatalf("EncryptInit: %v", err)
		}
		out, err := testCtx.EncryptUpdate(sh, nil)
		if err != nil {
			t.Fatalf("EncryptUpdate(empty): %v", err)
		}
		if len(out) != 0 {
			t.Fatalf("EncryptUpdate(empty) = %x, want empty", out)
		}
		if _, err := testCtx.EncryptFinal(sh); err != nil {
			t.Fatalf("EncryptFinal: %v", err)
		}
	})

	t.Run("SignVerify", func(t *testing.T) {
		sh := requireSession(t)
		pub, priv, err := genRSAKeyPairRaw(t, sh)
		if err != nil {
			t.Fatalf("GenerateKeyPair(RSA): %v", err)
		}
		mech := NewMechanism(CKM_SHA256_RSA_PKCS, nil)
		if err := testCtx.SignInit(sh, mech, priv); err != nil {
			t.Fatalf("SignInit: %v", err)
		}
		sig, err := testCtx.Sign(sh, nil)
		if err != nil {
			t.Fatalf("Sign(empty): %v", err)
		}
		if err := testCtx.VerifyInit(sh, mech, pub); err != nil {
			t.Fatalf("VerifyInit: %v", err)
		}
		if err := testCtx.Verify(sh, nil, sig); err != nil {
			t.Fatalf("Verify(empty, sig): %v", err)
		}
	})
}
