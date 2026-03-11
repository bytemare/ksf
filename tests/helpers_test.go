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
	"github.com/bytemare/ksf/argon2id"

	internalpbkdf2 "github.com/bytemare/ksf/pbkdf2"
	internalscrypt "github.com/bytemare/ksf/scrypt"
)

const (
	maxFuzzInputSize = 64
	testOutputLength = 16
)

var (
	testPassword       = []byte("password")
	unknownIdentifiers = []ksf.Identifier{0, 255}
)

type validationCase struct {
	wantIs  error
	name    string
	wantErr string
	params  []uint64
}

type algorithmCase struct {
	lengthErr             error
	fuzzAllowed           func(parameters []uint64) bool
	name                  string
	defaultParameters     []uint64
	customParameters      []uint64
	salt                  []byte
	validationCases       []validationCase
	recommendedSaltLength int
	identifier            ksf.Identifier
}

var algorithmCases = []algorithmCase{
	{
		name:                  "Argon2id",
		identifier:            ksf.Argon2id,
		defaultParameters:     []uint64{3, 65536, 4},
		customParameters:      []uint64{1, 8, 1},
		recommendedSaltLength: 16,
		salt:                  []byte("0123456789abcdef"),
		lengthErr:             argon2id.ErrOutputLength,
		validationCases: []validationCase{
			{name: "defaults"},
			{
				name:    "wrong arity",
				params:  []uint64{1, 2},
				wantErr: "invalid amount of Argon2id parameters: expected 3: time, memory, and threads",
				wantIs:  argon2id.ErrParams,
			},
			{
				name:    "time too small",
				params:  []uint64{0, 1, 1},
				wantErr: "invalid Argon2id parameter value: Argon2id time must be between 1 and 4294967295",
				wantIs:  argon2id.ErrParameterValue,
			},
			{
				name:    "time too large",
				params:  []uint64{uint64(math.MaxUint32) + 1, 1, 1},
				wantErr: "invalid Argon2id parameter value: Argon2id time must be between 1 and 4294967295",
				wantIs:  argon2id.ErrParameterValue,
			},
			{
				name:    "memory too small",
				params:  []uint64{1, 0, 1},
				wantErr: "invalid Argon2id parameter value: Argon2id memory must be between 1 and 4294967295",
				wantIs:  argon2id.ErrParameterValue,
			},
			{
				name:    "memory too large",
				params:  []uint64{1, uint64(math.MaxUint32) + 1, 1},
				wantErr: "invalid Argon2id parameter value: Argon2id memory must be between 1 and 4294967295",
				wantIs:  argon2id.ErrParameterValue,
			},
			{
				name:    "threads too small",
				params:  []uint64{1, 1, 0},
				wantErr: "invalid Argon2id parameter value: Argon2id threads must be between 1 and 255",
				wantIs:  argon2id.ErrParameterValue,
			},
			{
				name:    "threads too large",
				params:  []uint64{1, 1, 256},
				wantErr: "invalid Argon2id parameter value: Argon2id threads must be between 1 and 255",
				wantIs:  argon2id.ErrParameterValue,
			},
			{name: "valid minimums", params: []uint64{1, 1, 1}},
			{name: "valid maximums", params: []uint64{math.MaxUint32, math.MaxUint32, 255}},
		},
		fuzzAllowed: func(parameters []uint64) bool {
			return len(parameters) == 3 && parameters[0] <= 4 && parameters[1] <= 64 && parameters[2] <= 4
		},
	},
	{
		name:                  "PBKDF2-SHA512",
		identifier:            ksf.PBKDF2Sha512,
		defaultParameters:     []uint64{10000},
		customParameters:      []uint64{1},
		recommendedSaltLength: 8,
		salt:                  []byte("01234567"),
		lengthErr:             internalpbkdf2.ErrOutputLength,
		validationCases: []validationCase{
			{name: "defaults"},
			{
				name:    "wrong arity",
				params:  []uint64{1, 2},
				wantErr: "invalid amount of PBKDF2 parameters: expected 1: iterations",
				wantIs:  internalpbkdf2.ErrParams,
			},
			{
				name:   "iterations too small",
				params: []uint64{0},
				wantErr: fmt.Sprintf(
					"invalid PBKDF2 parameter value: PBKDF2 iterations must be between 1 and %d",
					math.MaxInt,
				),
				wantIs: internalpbkdf2.ErrParameterValue,
			},
			{
				name:   "iterations too large",
				params: []uint64{uint64(math.MaxInt) + 1},
				wantErr: fmt.Sprintf(
					"invalid PBKDF2 parameter value: PBKDF2 iterations must be between 1 and %d",
					math.MaxInt,
				),
				wantIs: internalpbkdf2.ErrParameterValue,
			},
			{name: "minimum valid iterations", params: []uint64{1}},
			{name: "maximum valid iterations", params: []uint64{math.MaxInt}},
		},
		fuzzAllowed: func(parameters []uint64) bool {
			return len(parameters) == 1 && parameters[0] <= 4096
		},
	},
	{
		name:                  "Scrypt",
		identifier:            ksf.Scrypt,
		defaultParameters:     []uint64{32768, 8, 1},
		customParameters:      []uint64{2, 1, 1},
		recommendedSaltLength: 16,
		salt:                  []byte("0123456789abcdef"),
		lengthErr:             internalscrypt.ErrOutputLength,
		validationCases: []validationCase{
			{name: "defaults"},
			{
				name:    "wrong arity",
				params:  []uint64{2, 1},
				wantErr: "invalid amount of Scrypt parameters: expected 3: N, r, and p",
				wantIs:  internalscrypt.ErrParams,
			},
			{
				name:   "n too small",
				params: []uint64{1, 1, 1},
				wantErr: fmt.Sprintf(
					"invalid Scrypt parameter value: scrypt N must be a power of 2 between 2 and %d",
					math.MaxInt,
				),
				wantIs: internalscrypt.ErrParameterValue,
			},
			{
				name:   "n not a power of two",
				params: []uint64{3, 1, 1},
				wantErr: fmt.Sprintf(
					"invalid Scrypt parameter value: scrypt N must be a power of 2 between 2 and %d",
					math.MaxInt,
				),
				wantIs: internalscrypt.ErrParameterValue,
			},
			{
				name:   "n too large",
				params: []uint64{uint64(math.MaxInt) + 1, 1, 1},
				wantErr: fmt.Sprintf(
					"invalid Scrypt parameter value: scrypt N must be a power of 2 between 2 and %d",
					math.MaxInt,
				),
				wantIs: internalscrypt.ErrParameterValue,
			},
			{
				name:    "r too small",
				params:  []uint64{2, 0, 1},
				wantErr: fmt.Sprintf("invalid Scrypt parameter value: Scrypt r must be between 1 and %d", math.MaxInt),
				wantIs:  internalscrypt.ErrParameterValue,
			},
			{
				name:    "r too large",
				params:  []uint64{2, uint64(math.MaxInt) + 1, 1},
				wantErr: fmt.Sprintf("invalid Scrypt parameter value: Scrypt r must be between 1 and %d", math.MaxInt),
				wantIs:  internalscrypt.ErrParameterValue,
			},
			{
				name:    "p too small",
				params:  []uint64{2, 1, 0},
				wantErr: fmt.Sprintf("invalid Scrypt parameter value: Scrypt p must be between 1 and %d", math.MaxInt),
				wantIs:  internalscrypt.ErrParameterValue,
			},
			{
				name:    "p too large",
				params:  []uint64{2, 1, uint64(math.MaxInt) + 1},
				wantErr: fmt.Sprintf("invalid Scrypt parameter value: Scrypt p must be between 1 and %d", math.MaxInt),
				wantIs:  internalscrypt.ErrParameterValue,
			},
			{
				name:    "overflowing combination",
				params:  []uint64{2, 1 << 29, 2},
				wantErr: "invalid Scrypt parameter value: parameter combination result is too large",
				wantIs:  internalscrypt.ErrParameterValue,
			},
			{name: "minimum valid parameters", params: []uint64{2, 1, 1}},
			{name: "default parameters", params: []uint64{32768, 8, 1}},
		},
		fuzzAllowed: func(parameters []uint64) bool {
			return len(parameters) == 3 && parameters[0] <= 16 && parameters[1] <= 8 && parameters[2] <= 4
		},
	},
}

func mustAlgorithmCase(identifier ksf.Identifier) algorithmCase {
	for _, tc := range algorithmCases {
		if tc.identifier == identifier {
			return tc
		}
	}

	panic(fmt.Sprintf("algorithm case not found for identifier %d", identifier))
}

func panicValue(f func()) (any, bool) {
	var report interface{}

	func() {
		defer func() {
			report = recover()
		}()

		f()
	}()

	if report == nil {
		return nil, false
	}

	return report, true
}

func assertError(t *testing.T, err, wantIs error, want string) {
	t.Helper()

	if err == nil {
		t.Fatalf("expected error %q, got nil", want)
	}

	if wantIs != nil && !errors.Is(err, wantIs) {
		t.Fatalf("expected wrapped error %v, got %v", wantIs, err)
	}

	if err.Error() != want {
		t.Fatalf("expected error %q, got %q", want, err)
	}
}

func assertPanicMessage(t *testing.T, want string, f func()) {
	t.Helper()

	got, panicked := panicValue(f)
	if !panicked {
		t.Fatalf("expected panic %q, got none", want)
	}

	if fmt.Sprint(got) != want {
		t.Fatalf("expected panic %q, got %q", want, got)
	}
}

func assertPanicError(t *testing.T, want error, f func()) {
	t.Helper()

	got, panicked := panicValue(f)
	if !panicked {
		t.Fatalf("expected panic %q, got none", want)
	}

	err, ok := got.(error)
	if !ok {
		t.Fatalf("expected panic error %q, got %T (%v)", want, got, got)
	}

	if !errors.Is(err, want) {
		t.Fatalf("expected panic matching %q, got %v", want, err)
	}

	if err.Error() != want.Error() {
		t.Fatalf("expected panic %q, got %q", want, err)
	}
}

func assertFreshSlice(t *testing.T, getter func() []uint64, want []uint64) {
	t.Helper()

	got := getter()
	if !slices.Equal(got, want) {
		t.Fatalf("expected default parameters %v, got %v", want, got)
	}

	if len(got) == 0 {
		return
	}

	got[0]++

	if !slices.Equal(getter(), want) {
		t.Fatalf("mutating the returned slice changed subsequent defaults: want %v", want)
	}
}

func hardenAndCompare(
	t *testing.T,
	identifier ksf.Identifier,
	password, salt []byte,
	length int,
	parameters ...uint64,
) []byte {
	t.Helper()

	out, err := identifier.Harden(password, salt, length, parameters...)
	if err != nil {
		t.Fatalf("unexpected harden error: %v", err)
	}

	if len(out) != length {
		t.Fatalf("unexpected output length: %d", len(out))
	}

	var unsafeOut []byte
	if got, panicked := panicValue(func() {
		unsafeOut = identifier.UnsafeHarden(password, salt, length, parameters...)
	}); panicked {
		t.Fatalf("unexpected panic: %q", got)
	}

	if !slices.Equal(out, unsafeOut) {
		t.Fatalf("Harden and UnsafeHarden diverged: %x / %x", out, unsafeOut)
	}

	return out
}

func assertInvalidLength(t *testing.T, tc algorithmCase, password, salt []byte, length int) {
	t.Helper()

	out, err := tc.identifier.Harden(password, salt, length, tc.customParameters...)
	if out != nil {
		t.Fatalf("expected nil output for invalid length, got %x", out)
	}

	assertError(t, err, tc.lengthErr, tc.lengthErr.Error())
	assertPanicError(t, tc.lengthErr, func() {
		_ = tc.identifier.UnsafeHarden(password, salt, length, tc.customParameters...)
	})
}

func runValidationCases(t *testing.T, tc algorithmCase) {
	t.Helper()

	for _, validation := range tc.validationCases {
		t.Run(validation.name, func(t *testing.T) {
			err := tc.identifier.VerifyParameters(validation.params...)
			if validation.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected validation error: %v", err)
				}

				return
			}

			assertError(t, err, validation.wantIs, validation.wantErr)
		})
	}
}

func assertUnknownIdentifierContract(t *testing.T, identifier ksf.Identifier, password, salt []byte, length int) {
	t.Helper()

	if got := identifier.RecommendedSaltLength(); got != 0 {
		t.Fatalf("unexpected salt length for unknown identifier: %d", got)
	}

	if params := identifier.DefaultParameters(); params != nil {
		t.Fatalf("expected nil default parameters, got %v", params)
	}

	assertError(t, identifier.VerifyParameters(1), ksf.ErrUnknownIdentifier, ksf.ErrUnknownIdentifier.Error())

	out, err := identifier.Harden(password, salt, length)
	if out != nil {
		t.Fatalf("expected nil output for unknown identifier, got %x", out)
	}

	assertError(t, err, ksf.ErrUnknownIdentifier, ksf.ErrUnknownIdentifier.Error())

	if got := identifier.String(); got != "Unknown KSF" {
		t.Fatalf("unexpected string for unknown identifier: %q", got)
	}

	assertPanicError(t, ksf.ErrUnknownIdentifier, func() {
		_ = identifier.UnsafeHarden(password, salt, length)
	})
	assertPanicError(t, ksf.ErrUnknownIdentifier, func() {
		_ = identifier.RandomSalt(length)
	})
}

func runValidateVsHardenConsistency(t *testing.T, tc algorithmCase, parameters []uint64, password, salt string) {
	t.Helper()

	if len(password) > maxFuzzInputSize || len(salt) > maxFuzzInputSize {
		t.Skip()
	}

	err := tc.identifier.VerifyParameters(parameters...)
	if err != nil {
		if out, hardenErr := tc.identifier.Harden([]byte(password), []byte(salt), testOutputLength, parameters...); out != nil ||
			hardenErr == nil {
			t.Fatalf("expected Harden error for invalid parameters, got out=%x err=%v", out, hardenErr)
		}

		assertPanicMessage(t, err.Error(), func() {
			_ = tc.identifier.UnsafeHarden([]byte(password), []byte(salt), testOutputLength, parameters...)
		})

		return
	}

	if tc.fuzzAllowed != nil && !tc.fuzzAllowed(parameters) {
		t.Skip()
	}

	out := hardenAndCompare(t, tc.identifier, []byte(password), []byte(salt), testOutputLength, parameters...)
	if len(out) != testOutputLength {
		t.Fatalf("unexpected fuzz output length: %d", len(out))
	}
}
