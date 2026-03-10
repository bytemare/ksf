// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package argon2id

import (
	"fmt"
	"math"

	"golang.org/x/crypto/argon2"
)

const (
	// Name is the string identifier for the Argon2id key stretching function.
	Name = "Argon2id"

	// RecommendedSaltLength is the RFC recommended salt length for the Argon2id key stretching function.
	RecommendedSaltLength = 16

	// DefaultTime is the default time parameter for the Argon2id key stretching function.
	DefaultTime = uint32(3)

	// DefaultMemory is the default memory parameter for the Argon2id key stretching function, in KiB.
	DefaultMemory = uint32(64 * 1024)

	// DefaultThreads is the default threads parameter for the Argon2id key stretching function.
	DefaultThreads = uint8(4)
)

var (
	// ErrParams indicates an invalid amount of Argon2id parameters.
	ErrParams = fmt.Errorf("invalid amount of Argon2id parameters")

	// ErrParameterValue indicates that one or more Argon2id parameters have invalid values.
	ErrParameterValue = fmt.Errorf("invalid Argon2id parameter value")
)

// DefaultParameters returns the default Argon2id parameters as a slice of uint64. The parameters are in the following order: time, memory, threads.
func DefaultParameters() []uint64 {
	return []uint64{uint64(DefaultTime), uint64(DefaultMemory), uint64(DefaultThreads)}
}

// ValidateParameters checks if the provided parameters are valid for the Argon2id key stretching function.
// The parameters must be in the following order: time, memory, threads.
func ValidateParameters(parameters ...uint64) error {
	if len(parameters) == 0 {
		return nil
	}

	if len(parameters) != 3 {
		return fmt.Errorf("%w: expected 3: time, memory, and threads", ErrParams)
	}

	if parameters[0] <= 0 || parameters[0] > math.MaxUint32 {
		return fmt.Errorf("%w: Argon2id time must be between 1 and %d", ErrParameterValue, math.MaxUint32)
	}

	if parameters[1] <= 0 || parameters[1] > math.MaxUint32 {
		return fmt.Errorf("%w: Argon2id memory must be between 1 and %d", ErrParameterValue, math.MaxUint32)
	}

	if parameters[2] <= 0 || parameters[2] > 255 {
		return fmt.Errorf("%w: Argon2id threads must be between 1 and 255", ErrParameterValue)
	}

	return nil
}

// Harden uses the Argon2id key stretching function to derive a key from the password and salt.
// The parameters are optional and must be in the following order: time, memory, threads. If no parameters are provided,
// the recommended default values will be used.
func Harden(password, salt []byte, length int, parameters ...uint64) ([]byte, error) {
	err := ValidateParameters(parameters...)
	if err != nil {
		return nil, err
	}

	time := DefaultTime
	memory := DefaultMemory
	threads := DefaultThreads

	if len(parameters) != 0 {
		time = uint32(parameters[0])
		memory = uint32(parameters[1])
		threads = uint8(parameters[2])
	}

	return argon2.IDKey(password, salt, time, memory, threads, uint32(length)), nil
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
