// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package ksf provides an interface to key stretching functions, a.k.a password key derivation functions.
package ksf

import (
	"errors"
	"fmt"

	cryptorand "crypto/rand"
)

var errParams = errors.New("invalid amount of parameters")

// Identifier is used to specify the key stretching function to be used.
type Identifier byte

const (
	// Argon2id password kdf function.
	Argon2id Identifier = 1 + iota

	// Scrypt password kdf function.
	Scrypt

	// PBKDF2Sha512 PBKDF2 password kdf function using SHA-512.
	PBKDF2Sha512

	// Bcrypt password kdf function.
	Bcrypt

	maxID
)

// Available reports whether the given kdf function is linked into the binary.
func (i Identifier) Available() bool {
	return i > 0 && i < maxID
}

// Get returns a KSF with default parameters.
func (i Identifier) Get() *KSF {
	var ksf keyStretchingFunction

	switch i {
	case Argon2id:
		ksf = argon2idNew()
	case Bcrypt:
		ksf = bcryptNew()
	case Scrypt:
		ksf = scryptKSFNew()
	case PBKDF2Sha512:
		ksf = pbkdf2New()
	default:
		return nil
	}

	return &KSF{ksf}
}

// Harden uses default parameters for the key derivation function over the input password and salt.
func (i Identifier) Harden(password, salt []byte, length int) []byte {
	return i.Get().Harden(password, salt, length)
}

// String returns the string name of the hashing function.
func (i Identifier) String() string {
	return i.Get().String()
}

type keyStretchingFunction interface {
	// Harden uses default parameters for the key derivation function over the input password and salt.
	Harden(password, salt []byte, length int) []byte

	// Parameterize replaces the functions parameters with the new ones. Must match the amount of parameters.
	Parameterize(parameters ...int)

	// String returns the string name of the function and its parameters.
	String() string

	// Params returns the list of internal parameters. If none was provided or modified, the recommended defaults values
	// are used.
	Params() []int
}

// KSF allows customisation of the underlying key stretching function.
type KSF struct {
	keyStretchingFunction
}

// Salt returns random bytes of length len (wrapper for crypto/rand).
func Salt(length int) []byte {
	s := make([]byte, length)
	if _, err := cryptorand.Read(s); err != nil {
		// We can as well not panic and try again in a loop and a counter to stop.
		panic(fmt.Errorf("unexpected error in generating a salt : %w", err))
	}

	return s
}
