// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ksf_test

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"testing"

	"github.com/bytemare/ksf"
)

var (
	errNoPanic         = errors.New("no panic")
	errNoPanicMessage  = errors.New("panic but no message")
	errPBKDFParams     = errors.New("invalid amount of PBKDF2 parameters: expected 1: iterations")
	errArgon2idThreads = errors.New("invalid Argon2id parameter value: Argon2id threads must be between 1 and 255")
)

func hasPanic(f func()) (has bool, err error) {
	err = nil
	var report interface{}
	func() {
		defer func() {
			if report = recover(); report != nil {
				has = true
			}
		}()

		f()
	}()

	if has {
		err = fmt.Errorf("%v", report)
	}

	return has, err
}

// expectPanic executes the function f with the expectation to recover from a panic. If no panic occurred or if the
// panic message is not the one expected, ExpectPanic returns (false, error).
func expectPanic(expectedError error, f func()) (bool, error) {
	hasPanic, err := hasPanic(f)

	if !hasPanic {
		return false, errNoPanic
	}

	if expectedError == nil {
		return true, nil
	}

	if err == nil {
		return false, errNoPanicMessage
	}

	if err.Error() != expectedError.Error() {
		return false, fmt.Errorf("expected %q, got: %w", expectedError, err)
	}

	return true, nil
}

func expectError(expectedError error, f func() error) error {
	err := f()

	if err == nil {
		return fmt.Errorf("expected error did not occur. Want %q, got %q", expectedError, err)
	}

	if expectedError != nil && err.Error() != expectedError.Error() {
		return fmt.Errorf("expected error did not occur. Want %q, got %q", expectedError, err)
	}

	return nil
}

type ksfProperties struct {
	name       string
	parameters []uint64
	saltLength int
	identifier ksf.Identifier
}

var ksfs = []ksfProperties{
	{
		identifier: ksf.Argon2id,
		name:       "Argon2id",
		parameters: []uint64{3, 65536, 4},
		saltLength: 16,
	},
	{
		identifier: ksf.PBKDF2Sha512,
		name:       "PBKDF2-SHA512",
		parameters: []uint64{10000},
		saltLength: 8,
	},
	{
		identifier: ksf.Scrypt,
		name:       "Scrypt",
		parameters: []uint64{32768, 8, 1},
		saltLength: 16,
	},
}

func TestAvailability(t *testing.T) {
	for _, i := range ksfs {
		if !i.identifier.Available() {
			t.Errorf("%s is not available, but should be", i.identifier)
		}
	}

	wrong := 0
	if ksf.Identifier(wrong).Available() {
		t.Errorf("%v is considered available when it should not", wrong)
	}
}

func TestKSF(t *testing.T) {
	password := []byte("password")
	length := 32

	for _, m := range ksfs {
		t.Run(m.identifier.String(), func(t *testing.T) {
			if !m.identifier.Available() {
				t.Fatal("expected KSF to be available, but it is not")
			}

			if m.identifier.RecommendedSaltLength() != m.saltLength {
				t.Fatalf("not equal, %d / %d", m.identifier.RecommendedSaltLength(), m.saltLength)
			}

			if !slices.Equal(m.identifier.DefaultParameters(), m.parameters) {
				t.Fatalf("not equal, %v / %v", m.identifier.DefaultParameters(), m.parameters)
			}

			if m.identifier.String() != m.name {
				t.Fatalf("not equal, %s / %s", m.identifier.String(), m.name)
			}

			var h1, h2 []byte
			salt := m.identifier.RandomSalt(m.identifier.RecommendedSaltLength())

			h1, err := m.identifier.Harden(password, salt, length)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if hasPanic, err := expectPanic(nil, func() {
				h2 = m.identifier.UnsafeHarden(password, salt, length)
			}); hasPanic {
				t.Fatalf("expected panic did not occur: %v", err)
			}

			if string(h1) != string(h2) {
				t.Fatalf("not equal, %s / %s", string(h1), string(h2))
			}
		})
	}
}

func TestErrorScrypt(t *testing.T) {
	h := ksf.Scrypt
	password := []byte("password")
	salt := h.RandomSalt(32)
	outputLength := 32

	// Wrong number of parameters
	if err := expectError(nil, func() error {
		return h.VerifyParameters(1, 2, 3, 4)
	}); err != nil {
		t.Fatal(err)
	}

	// n = 1
	if err := expectError(nil, func() error {
		return h.VerifyParameters(1, 8, 2)
	}); err != nil {
		t.Fatal(err)
	}

	if hasPanic, err := expectPanic(nil, func() {
		_ = h.UnsafeHarden(password, salt, outputLength, 1, 8, 2)
	}); !hasPanic {
		t.Fatalf("expected panic did not occur: %v", err)
	}

	// r = 0
	if err := expectError(nil, func() error {
		return h.VerifyParameters(32768, 0, 2)
	}); err != nil {
		t.Fatal(err)
	}

	// big r and p
	n, r, p := 32768, math.MaxInt32, math.MaxInt32

	if err := expectError(nil, func() error {
		_, err := h.Harden(password, salt, outputLength, uint64(n), uint64(r), uint64(p))
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCrashArgon2id(t *testing.T) {
	// Wrong number of parameters
	if err := expectError(nil, func() error {
		return ksf.Argon2id.VerifyParameters(1, 2, 3, 4)
	}); err != nil {
		t.Fatal(err)
	}

	// Too many threads
	if hasPanic, err := expectPanic(errArgon2idThreads, func() {
		ksf.Argon2id.UnsafeHarden(nil, nil, 0, 1, 2, 256)
	}); !hasPanic {
		t.Fatalf("expected panic did not occur: %v", err)
	}
}

func TestCrashPBKDF2(t *testing.T) {
	// Wrong number of parameters
	if hasPanic, err := expectPanic(errPBKDFParams, func() {
		ksf.PBKDF2Sha512.UnsafeHarden(nil, nil, 0, 1, 2)
	}); !hasPanic {
		t.Fatalf("expected panic did not occur: %v", err)
	}
}
