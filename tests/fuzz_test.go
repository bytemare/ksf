// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ksf_test

import (
	"testing"

	"github.com/bytemare/ksf"
)

func FuzzIdentifierContract(f *testing.F) {
	f.Add(uint8(0), "", "", 16)
	f.Add(uint8(1), "password", "salt", 16)
	f.Add(uint8(2), "password", "salt", 16)
	f.Add(uint8(3), "password", "salt", 16)
	f.Add(uint8(255), "password", "salt", 16)
	f.Add(uint8(1), "password", "salt", 0)
	f.Add(uint8(2), "password", "salt", -1)

	f.Fuzz(func(t *testing.T, rawID uint8, password, salt string, length int) {
		id := ksf.Identifier(rawID)

		if !id.Available() {
			assertUnknownIdentifierContract(t, id, []byte(password), []byte(salt), length)
			return
		}

		tc := mustAlgorithmCase(id)

		if err := id.VerifyParameters(tc.customParameters...); err != nil {
			t.Fatalf("VerifyParameters rejected cheap valid parameters: %v", err)
		}

		switch {
		case length <= 0:
			assertInvalidLength(t, tc, []byte(password), []byte(salt), length)
		case length > 64:
			t.Skip()
		default:
			hardenAndCompare(t, id, []byte(password), []byte(salt), length, tc.customParameters...)
		}
	})
}

func FuzzArgon2idValidateVsHardenConsistency(f *testing.F) {
	tc := mustAlgorithmCase(ksf.Argon2id)
	f.Add(uint64(1), uint64(8), uint64(1), "password", "salt")
	f.Add(uint64(0), uint64(8), uint64(1), "password", "salt")
	f.Add(uint64(1), uint64(8), uint64(256), "password", "salt")

	f.Fuzz(func(t *testing.T, timeParam, memoryParam, threadsParam uint64, password, salt string) {
		runValidateVsHardenConsistency(t, tc, []uint64{timeParam, memoryParam, threadsParam}, password, salt)
	})
}

func FuzzPBKDF2ValidateVsHardenConsistency(f *testing.F) {
	tc := mustAlgorithmCase(ksf.PBKDF2Sha512)
	f.Add(uint64(1), "password", "salt")
	f.Add(uint64(0), "password", "salt")
	f.Add(uint64(4096), "password", "salt")

	f.Fuzz(func(t *testing.T, iterations uint64, password, salt string) {
		runValidateVsHardenConsistency(t, tc, []uint64{iterations}, password, salt)
	})
}

func FuzzScryptValidateVsHardenConsistency(f *testing.F) {
	tc := mustAlgorithmCase(ksf.Scrypt)
	f.Add(uint64(2), uint64(1), uint64(1), "password", "salt")
	f.Add(uint64(1), uint64(1), uint64(1), "password", "salt")
	f.Add(uint64(2), uint64(1<<29), uint64(2), "password", "salt")

	f.Fuzz(func(t *testing.T, n, r, p uint64, password, salt string) {
		runValidateVsHardenConsistency(t, tc, []uint64{n, r, p}, password, salt)
	})
}
