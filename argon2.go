// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ksf

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	argon2ids      = "Argon2id"
	argon2idFormat = "%s(%d-%d-%d)"
)

var errArgon2idThreads = errors.New("number of threads cannot be above 255")

type argon2KSF struct {
	time, memory uint32
	threads      uint8
}

func argon2idNew() *argon2KSF {
	var (
		defaultArgon2idTime    = uint32(3)
		defaultArgon2idMemory  = uint32(64 * 1024)
		defaultArgon2idThreads = uint8(4)
	)

	return &argon2KSF{
		time:    defaultArgon2idTime,
		memory:  defaultArgon2idMemory,
		threads: defaultArgon2idThreads,
	}
}

// Identifier returns the KSF identifier.
func (a *argon2KSF) Identifier() Identifier {
	return Argon2id
}

// RecommendedSaltLength returns the RFC recommended salt length for the Argon2id key stretching function.
func (a *argon2KSF) RecommendedSaltLength() int {
	return 16
}

// Harden uses the Argon2id key stretching function to derive a key from the password and salt.
func (a *argon2KSF) Harden(password, salt []byte, length int) []byte {
	return argon2.IDKey(password, salt, a.time, a.memory, a.threads, uint32(length))
}

// Parameterize replaces the functions parameters with the new ones. Must match the amount of parameters.
func (a *argon2KSF) Parameterize(parameters ...int) {
	if len(parameters) != 3 {
		panic(errParams)
	}

	if parameters[2] > 255 {
		panic(errArgon2idThreads)
	}

	a.time = uint32(parameters[0])
	a.memory = uint32(parameters[1])
	a.threads = uint8(parameters[2])
}

// String returns the KSF name and list of parameters as a string.
func (a *argon2KSF) String() string {
	return fmt.Sprintf(argon2idFormat, argon2ids, a.time, a.memory, a.threads)
}

// Parameters returns the parameters used by the KSF. If none was provided or modified, the recommended defaults value.
func (a *argon2KSF) Parameters() []int {
	return []int{int(a.time), int(a.memory), int(a.threads)}
}
