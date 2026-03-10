// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package pbkdf2

import (
	"crypto/sha512"
	"fmt"
	"math"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// Name is the string identifier for the PBKDF2 key stretching function.
	Name = "PBKDF2-SHA512"

	// RecommendedSaltLength is the RFC recommended salt length for the PBKDF2 key stretching function.
	RecommendedSaltLength = 8

	// DefaultIterations is the default iterations parameter for the PBKDF2 key stretching function.
	DefaultIterations = 10000
)

var (
	// ErrParams indicates an invalid amount of PBKDF2 parameters.
	ErrParams = fmt.Errorf("invalid amount of PBKDF2 parameters")

	// ErrParameterValue indicates that one or more PBKDF2 parameters have invalid values.
	ErrParameterValue = fmt.Errorf("invalid PBKDF2 parameter value")
)

// DefaultParameters returns the default PBKDF2 iterations parameter as a slice of uint64.
func DefaultParameters() []uint64 {
	return []uint64{uint64(DefaultIterations)}
}

// ValidateParameters checks if the provided parameter is valid for the PBKDF2 key stretching function.
// The parameter must be empty or a single value representing the number of iterations.
func ValidateParameters(parameters ...uint64) error {
	if len(parameters) == 0 {
		return nil
	}

	if len(parameters) != 1 {
		return fmt.Errorf("%w: expected 1: iterations", ErrParams)
	}

	if parameters[0] <= 0 || parameters[0] > math.MaxInt {
		return fmt.Errorf("%w: PBKDF2 iterations must be between 1 and %d", ErrParameterValue, math.MaxInt)
	}

	return nil
}

// Harden uses the PBKDF2 key stretching function to derive a key from the password and salt.
// The parameter must be empty or a single value representing the number of iterations.
// If no parameters are provided, the recommended default values will be used.
func Harden(password, salt []byte, length int, parameters ...uint64) ([]byte, error) {
	err := ValidateParameters(parameters...)
	if err != nil {
		return nil, err
	}

	iterations := DefaultIterations

	if len(parameters) != 0 {
		iterations = int(parameters[0])
	}

	return pbkdf2.Key(password, salt, iterations, length, sha512.New), nil
}

// UnsafeHarden is the same as Harden but panics on an invalid parameter.
// It is safe to use if the parameter has previously been validated by ValidateParameters.
func UnsafeHarden(password, salt []byte, length int, parameters ...uint64) []byte {
	out, err := Harden(password, salt, length, parameters...)
	if err != nil {
		panic(err)
	}

	return out
}
