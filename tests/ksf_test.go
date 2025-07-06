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
	"testing"

	"github.com/bytemare/ksf"
)

var (
	errNoPanic         = errors.New("no panic")
	errNoPanicMessage  = errors.New("panic but no message")
	errParams          = errors.New("invalid amount of parameters")
	errArgon2idThreads = errors.New("number of threads cannot be above 255")
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

type ksfProperties struct {
	string
	saltLength int
	Identifier ksf.Identifier
}

var ksfs = []ksfProperties{
	{
		Identifier: ksf.Argon2id,
		string:     "Argon2id(3-65536-4)",
		saltLength: 16,
	},
	{
		Identifier: ksf.PBKDF2Sha512,
		string:     "PBKDF2(10000-SHA512)",
		saltLength: 8,
	},
	{
		Identifier: ksf.Scrypt,
		string:     "Scrypt(32768-8-1)",
		saltLength: 16,
	},
}

func TestAvailability(t *testing.T) {
	for _, i := range ksfs {
		if !i.Identifier.Available() {
			t.Errorf("%s is not available, but should be", i.Identifier)
		}
	}

	wrong := 0
	if ksf.Identifier(wrong).Available() {
		t.Errorf("%v is considered available when it should not", wrong)
	}
}

func TestKSF(t *testing.T) {
	password := []byte("password")
	salt := ksf.Salt(32)
	length := 32

	for _, m := range ksfs {
		t.Run(m.Identifier.String(), func(t *testing.T) {
			if !m.Identifier.Available() {
				t.Fatal("expected KSF to be available, but it is not")
			}

			if m.Identifier.String() != m.string {
				t.Fatalf("not equal, %s / %s", m.Identifier.String(), m.string)
			}

			var h1, h2 []byte

			if hasPanic, _ := expectPanic(nil, func() {
				h1 = m.Identifier.Harden(password, salt, length)
			}); hasPanic {
				t.Fatal("unexpected panic")
			}

			h := m.Identifier.Get()

			if h.Identifier() != m.Identifier {
				t.Fatalf("not equal, %s / %s", h.Identifier(), m.Identifier)
			}

			h.Parameterize(h.Parameters()...)
			if hasPanic, _ := expectPanic(nil, func() {
				h2 = h.Harden(password, salt, length)
			}); hasPanic {
				t.Fatal("unexpected panic")
			}

			if string(h1) != string(h2) {
				t.Fatalf("not equal, %s / %s", string(h1), string(h2))
			}
		})
	}
}

func TestCrashScrypt(t *testing.T) {
	h := ksf.Scrypt.Get()
	password := []byte("password")
	salt := ksf.Salt(32)
	outputLength := 32

	// Wrong number of parameters
	if hasPanic, _ := expectPanic(errParams, func() {
		h.Parameterize(1, 2, 3, 4)
	}); !hasPanic {
		t.Fatal("expected panic did not occur")
	}

	// n = 1
	h.Parameterize(1, 8, 1)
	if hasPanic, _ := expectPanic(nil, func() {
		_ = h.Harden(password, salt, outputLength)
	}); !hasPanic {
		t.Fatal("expected panic did not occur")
	}

	// big r and p
	h.Parameterize(32768, math.MaxInt32, math.MaxInt32)
	if hasPanic, _ := expectPanic(nil, func() {
		_ = h.Harden(password, salt, outputLength)
	}); !hasPanic {
		t.Fatal("expected panic did not occur")
	}
}

func TestCrashArgon2(t *testing.T) {
	// Wrong number of parameters
	if hasPanic, _ := expectPanic(errParams, func() {
		ksf.Argon2id.Get().Parameterize(1, 2, 3, 4)
	}); !hasPanic {
		t.Fatal("expected panic did not occur")
	}

	// Too many threads
	if hasPanic, _ := expectPanic(errArgon2idThreads, func() {
		ksf.Argon2id.Get().Parameterize(1, 2, 256)
	}); !hasPanic {
		t.Fatal("expected panic did not occur")
	}
}

func TestCrashPBKDF2(t *testing.T) {
	// Wrong number of parameters
	if hasPanic, _ := expectPanic(errParams, func() {
		ksf.PBKDF2Sha512.Get().Parameterize(1, 2)
	}); !hasPanic {
		t.Fatal("expected panic did not occur")
	}
}
