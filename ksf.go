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

	"github.com/bytemare/ksf/argon2id"
	"github.com/bytemare/ksf/pbkdf2"
	"github.com/bytemare/ksf/scrypt"

	cryptorand "crypto/rand"
)

// Identifier is used to specify the key stretching function to be used.
type Identifier byte

const (
	// Argon2id password kdf function.
	Argon2id Identifier = 1 + iota

	// Scrypt password kdf function.
	Scrypt

	// PBKDF2Sha512 PBKDF2 password kdf function using SHA-512.
	PBKDF2Sha512

	// to add any new KSF, add its identifier above maxID to preserve the iota increment.
	maxID
)

// ErrUnknownIdentifier indicates that the requested KSF identifier is not registered.
// Callers can use errors.Is with this sentinel to detect unsupported identifiers.
var ErrUnknownIdentifier = errors.New("KSF identifier not recognized")

//nolint:gochecknoinits // Static registration keeps the identifier dispatch table explicit in one place.
func init() {
	register(
		Argon2id,
		argon2id.Name,
		argon2id.RecommendedSaltLength,
		argon2id.DefaultParameters,
		argon2id.ValidateParameters,
		argon2id.Harden,
		argon2id.UnsafeHarden,
	)
	register(
		Scrypt,
		scrypt.Name,
		scrypt.RecommendedSaltLength,
		scrypt.DefaultParameters,
		scrypt.ValidateParameters,
		scrypt.Harden,
		scrypt.UnsafeHarden,
	)
	register(
		PBKDF2Sha512,
		pbkdf2.Name,
		pbkdf2.RecommendedSaltLength,
		pbkdf2.DefaultParameters,
		pbkdf2.ValidateParameters,
		pbkdf2.Harden,
		pbkdf2.UnsafeHarden,
	)
}

//nolint:gochecknoglobals // The registry is fixed at init time and only used for read-only dispatch.
var (
	names                 = make(map[Identifier]string, maxID)
	recommendedSaltLength = map[Identifier]int{}
	defaultParameters     = make(map[Identifier]func() []uint64, maxID)
	parameterChecks       = make(map[Identifier]func(parameters ...uint64) error, maxID)
	hardeners             = make(map[Identifier]hardener, maxID)
	unsafeHardeners       = make(map[Identifier]unsafeHardener, maxID)
)

type (
	hardener       func(password, salt []byte, length int, parameters ...uint64) ([]byte, error)
	unsafeHardener func(password, salt []byte, length int, parameters ...uint64) []byte
)

func register(
	i Identifier,
	name string,
	saltLength int,
	d func() []uint64,
	p func(parameters ...uint64) error,
	h hardener,
	uh unsafeHardener,
) {
	names[i] = name
	recommendedSaltLength[i] = saltLength
	defaultParameters[i] = d
	parameterChecks[i] = p
	hardeners[i] = h
	unsafeHardeners[i] = uh
}

// Available reports whether the given kdf function is registered and linked into the binary.
func (i Identifier) Available() bool {
	return i > 0 && i < maxID && names[i] != ""
}

// RecommendedSaltLength returns the RFC recommended salt length for the KSF.
//
// If the KSF identifier is not recognized, 0 is returned.
func (i Identifier) RecommendedSaltLength() int {
	if !i.Available() {
		return 0
	}

	return recommendedSaltLength[i]
}

// DefaultParameters returns the default parameters for the KSF.
//
// If the KSF identifier is not recognized, nil is returned.
func (i Identifier) DefaultParameters() []uint64 {
	if !i.Available() {
		return nil
	}

	return defaultParameters[i]()
}

// VerifyParameters checks whether the provided parameters are valid for the
// KSF specified by the identifier.
// Unsupported identifiers return ErrUnknownIdentifier.
func (i Identifier) VerifyParameters(parameters ...uint64) error {
	if !i.Available() {
		return ErrUnknownIdentifier
	}

	return parameterChecks[i](parameters...)
}

// Harden derives a key from the password and salt using the KSF specified by
// the identifier, with the given parameters.
// Unsupported identifiers return ErrUnknownIdentifier.
func (i Identifier) Harden(password, salt []byte, length int, parameters ...uint64) ([]byte, error) {
	if !i.Available() {
		return nil, ErrUnknownIdentifier
	}

	return hardeners[i](password, salt, length, parameters...)
}

// UnsafeHarden is the same as Harden but panics if the KSF identifier is not
// recognized or the parameters are invalid, and does not return an error.
// It is the caller's responsibility to ensure that the parameters are valid for the KSF.
func (i Identifier) UnsafeHarden(password, salt []byte, length int, parameters ...uint64) []byte {
	if !i.Available() {
		panic(ErrUnknownIdentifier)
	}

	return unsafeHardeners[i](password, salt, length, parameters...)
}

// String returns the KSF name as a string.
//
// If the KSF identifier is not recognized, "Unknown KSF" is returned.
func (i Identifier) String() string {
	if !i.Available() {
		return "Unknown KSF"
	}

	return names[i]
}

// RandomSalt returns random bytes of the given length (wrapping crypto/rand),
// if length is not a positive integer, the recommended salt length for the KSF will be used.
//
// Panics with ErrUnknownIdentifier if the KSF identifier is not recognized.
func (i Identifier) RandomSalt(length int) []byte {
	if !i.Available() {
		panic(ErrUnknownIdentifier)
	}

	if length <= 0 {
		length = i.RecommendedSaltLength()
	}

	s := make([]byte, length)
	//nolint:errcheck // crypto/rand.Read is documented to never return a recoverable error.
	_, _ = cryptorand.Read(s)

	return s
}
