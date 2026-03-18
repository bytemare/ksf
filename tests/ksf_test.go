// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ksf_test

import (
	"slices"
	"testing"
)

func TestAvailability(t *testing.T) {
	for _, tc := range algorithmCases {
		if !tc.identifier.Available() {
			t.Errorf("%s is not available, but should be", tc.identifier)
		}
	}

	for _, wrong := range unknownIdentifiers {
		if wrong.Available() {
			t.Errorf("%v is considered available when it should not", wrong)
		}
	}
}

func TestIdentifierMetadataAndHardening(t *testing.T) {
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.identifier.Available() {
				t.Fatal("expected KSF to be available, but it is not")
			}

			if tc.identifier.RecommendedSaltLength() != tc.recommendedSaltLength {
				t.Fatalf("not equal, %d / %d", tc.identifier.RecommendedSaltLength(), tc.recommendedSaltLength)
			}

			if !slices.Equal(tc.identifier.DefaultParameters(), tc.defaultParameters) {
				t.Fatalf("not equal, %v / %v", tc.identifier.DefaultParameters(), tc.defaultParameters)
			}

			if err := tc.identifier.VerifyParameters(tc.defaultParameters...); err != nil {
				t.Fatalf("unexpected default parameter error: %v", err)
			}

			if err := tc.identifier.VerifyParameters(tc.customParameters...); err != nil {
				t.Fatalf("unexpected custom parameter error: %v", err)
			}

			if tc.identifier.String() != tc.name {
				t.Fatalf("not equal, %s / %s", tc.identifier.String(), tc.name)
			}

			defaultOut := hardenAndCompare(t, tc.identifier, testPassword, tc.salt, testOutputLength)
			customOut := hardenAndCompare(
				t,
				tc.identifier,
				testPassword,
				tc.salt,
				testOutputLength,
				tc.customParameters...)

			if slices.Equal(defaultOut, customOut) {
				t.Fatal("expected custom parameters to affect the derived key")
			}
		})
	}
}

func TestIdentifierDefaultParametersReturnsFreshSlice(t *testing.T) {
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			assertFreshSlice(t, tc.identifier.DefaultParameters, tc.defaultParameters)
		})
	}
}

func TestIdentifierValidationCases(t *testing.T) {
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			runValidationCases(t, tc)
		})
	}
}

func TestUnknownIdentifierContract(t *testing.T) {
	for _, id := range unknownIdentifiers {
		t.Run(id.String(), func(t *testing.T) {
			assertUnknownIdentifierContract(t, id, testPassword, []byte("salt"), testOutputLength)
		})
	}
}

func TestRandomSalt(t *testing.T) {
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			if salt := tc.identifier.RandomSalt(3); len(salt) != 3 {
				t.Fatalf("unexpected explicit salt length: %d", len(salt))
			}

			if salt := tc.identifier.RandomSalt(0); len(salt) != tc.recommendedSaltLength {
				t.Fatalf("unexpected fallback salt length for zero input: %d", len(salt))
			}

			if salt := tc.identifier.RandomSalt(-1); len(salt) != tc.recommendedSaltLength {
				t.Fatalf("unexpected fallback salt length for negative input: %d", len(salt))
			}
		})
	}
}

func TestIdentifierInvalidLength(t *testing.T) {
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, length := range []int{0, -1} {
				assertInvalidLength(t, tc, testPassword, tc.salt, length)
			}
		})
	}
}
