// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package scrypt

import (
	"fmt"
	"math"

	"golang.org/x/crypto/scrypt"
)

const (
	// Name is the string identifier for the Scrypt key stretching function.
	Name = "Scrypt"

	// RecommendedSaltLength is the RFC recommended salt length for the Scrypt key stretching function.
	RecommendedSaltLength = 16

	// DefaultN is the default N parameter for the Scrypt key stretching function.
	DefaultN = 32768

	// DefaultR is the default r parameter for the Scrypt key stretching function.
	DefaultR = 8

	// DefaultP is the default p parameter for the Scrypt key stretching function.
	DefaultP = 1
)

var (
	// ErrParams indicates an invalid amount of Scrypt parameters.
	ErrParams = fmt.Errorf("invalid amount of Scrypt parameters")

	// ErrParameterValue indicates that one or more Scrypt parameters have invalid values.
	ErrParameterValue = fmt.Errorf("invalid Scrypt parameter value")
)

// DefaultParameters returns the default Scrypt parameters as a slice of uint64. The parameters are in the following order: n, r, and p.
func DefaultParameters() []uint64 {
	return []uint64{uint64(DefaultN), uint64(DefaultR), uint64(DefaultP)}
}

// ValidateParameters checks if the provided parameters are valid for the Scrypt key stretching function.
// The parameters must be in the following order: n, r, and p.
func ValidateParameters(parameters ...uint64) error {
	if len(parameters) == 0 {
		return nil
	}

	if len(parameters) != 3 {
		return fmt.Errorf("%w: expected 3: time, memory, and threads", ErrParams)
	}

	n := parameters[0]
	r := parameters[1]
	p := parameters[2]

	// N must be a power of two greater than 1 and fit into an int.
	if n <= 1 || n > math.MaxInt || n&(n-1) != 0 {
		return fmt.Errorf("%w: scrypt N must be a power of 2 between 2 and %d", ErrParameterValue, math.MaxInt)
	}

	//  r and p must be greater than zero and fit into an int.
	if r == 0 || r > math.MaxInt {
		return fmt.Errorf("%w: scrypt memory must be between 1 and %d", ErrParameterValue, math.MaxInt/256)
	}

	if p == 0 || p > math.MaxInt {
		return fmt.Errorf("%w: scrypt threads must be between 1 and 255", ErrParameterValue)
	}

	// reusing the same check as the scrypt library to prevent integer overflow in later allocations and size calculations.
	if r*p >= 1<<30 || r > math.MaxInt/128/p || r > math.MaxInt/256 || n > math.MaxInt/128/r {
		return fmt.Errorf("%w: parameter combination result is too large", ErrParameterValue)
	}

	return nil
}

// Harden uses the Scrypt key stretching function to derive a key from the password and salt.
// The parameters are optional and must be in the following order: n, r, and p. If no parameters are provided,
// the recommended default values will be used.
func Harden(password, salt []byte, length int, parameters ...uint64) ([]byte, error) {
	err := ValidateParameters(parameters...)
	if err != nil {
		return nil, err
	}

	n := DefaultN
	r := DefaultR
	p := DefaultP

	if len(parameters) != 0 {
		n = int(parameters[0])
		r = int(parameters[1])
		p = int(parameters[2])
	}

	return scrypt.Key(password, salt, n, r, p, length)
}

// UnsafeHarden is the same as Harden but panics on invalid parameters. It is safe to use if parameters have
// previously been validated by ValidateParameters.
func UnsafeHarden(password, salt []byte, length int, parameters ...uint64) []byte {
	out, err := Harden(password, salt, length, parameters...)
	if err != nil {
		panic(err)
	}

	return out
}
