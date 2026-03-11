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

	"github.com/bytemare/ksf"
)

func ExampleIdentifier_Harden() {
	salt := []byte("0123456789abcdef")
	key, err := ksf.Argon2id.Harden([]byte("password"), salt, 32)
	if err != nil {
		panic(err)
	}

	fmt.Println(len(key))
	// Output: 32
}

func ExampleIdentifier_Harden_customParameters() {
	parameters := []uint64{1}
	if err := ksf.PBKDF2Sha512.VerifyParameters(parameters...); err != nil {
		panic(err)
	}

	key, err := ksf.PBKDF2Sha512.Harden([]byte("password"), []byte("01234567"), 16, parameters...)
	if err != nil {
		panic(err)
	}

	fmt.Println(len(key))
	// Output: 16
}

func ExampleErrUnknownIdentifier() {
	_, err := ksf.Identifier(0).Harden([]byte("password"), []byte("salt"), 16)
	fmt.Println(errors.Is(err, ksf.ErrUnknownIdentifier))
	// Output: true
}
