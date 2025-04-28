// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package tests_test

import (
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/bytemare/ksf"
)

var (
	errNoPanic        = errors.New("no panic")
	errNoPanicMessage = errors.New("panic but no message")
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

var (
	ksfs    = []ksf.Identifier{ksf.Argon2id, ksf.Bcrypt, ksf.PBKDF2Sha512, ksf.Scrypt}
	strings = []string{"Argon2id(3-65536-4)", "Scrypt(32768-8-1)", "PBKDF2(10000-SHA512)", "Bcrypt(10)"}
)

func TestAvailability(t *testing.T) {
	for _, i := range ksfs {
		if !i.Available() {
			t.Errorf("%s is not available, but should be", i)
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
		t.Run(m.String(), func(t *testing.T) {
			if !m.Available() {
				t.Fatal("expected assertion to be true")
			}

			if m.String() != strings[m-1] {
				t.Fatal("not equal")
			}

			if hasPanic, _ := expectPanic(nil, func() {
				_ = m.Harden(password, salt, length)
			}); hasPanic {
				t.Fatal("unexpected panic")
			}

			h := m.Get()
			h.Parameterize(h.Params()...)
			if hasPanic, _ := expectPanic(nil, func() {
				_ = m.Harden(password, salt, length)
			}); hasPanic {
				t.Fatal("unexpected panic")
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
	if hasPanic, _ := expectPanic(nil, func() {
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

func TestCrashBcrypt(t *testing.T) {
	h := ksf.Bcrypt.Get()

	_ = h.Harden(nil, nil, 0)

	// Wrong number of parameters
	if hasPanic, _ := expectPanic(nil, func() {
		h.Parameterize(1, 2)
	}); !hasPanic {
		t.Fatal("expected panic did not occur")
	}

	// high cost
	h.Parameterize(32)
	if hasPanic, _ := expectPanic(nil, func() {
		_ = h.Harden([]byte("password"), nil, 0)
	}); !hasPanic {
		t.Fatal("expected panic did not occur")
	}
}

func TestCrashArgon2(t *testing.T) {
	// Wrong number of parameters
	if hasPanic, _ := expectPanic(nil, func() {
		ksf.Argon2id.Get().Parameterize(1, 2, 3, 4)
	}); !hasPanic {
		t.Fatal("expected panic did not occur")
	}
}

func TestCrashPBKDF2(t *testing.T) {
	// Wrong number of parameters
	if hasPanic, _ := expectPanic(nil, func() {
		ksf.PBKDF2Sha512.Get().Parameterize(1, 2)
	}); !hasPanic {
		t.Fatal("expected panic did not occur")
	}
}
