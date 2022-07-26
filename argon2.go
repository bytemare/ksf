// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ksf

import (
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	argon2ids      = "Argon2id"
	argon2idFormat = "%s(%d-%d-%d)"
)

var (
	defaultArgon2idTime    = 3
	defaultArgon2idMemory  = 64 * 1024
	defaultArgon2idThreads = 4
)

type argon2KSF struct {
	time, memory, threads int
}

func argon2idNew() keyStretchingFunction {
	return &argon2KSF{
		time:    defaultArgon2idTime,
		memory:  defaultArgon2idMemory,
		threads: defaultArgon2idThreads,
	}
}

func (a *argon2KSF) Harden(password, salt []byte, length int) []byte {
	return argon2.IDKey(password, salt, uint32(a.time), uint32(a.memory), uint8(a.threads), uint32(length))
}

// Parameterize replaces the functions parameters with the new ones. Must match the amount of parameters.
func (a *argon2KSF) Parameterize(parameters ...int) {
	if len(parameters) != 3 {
		panic(errParams)
	}

	a.time = parameters[0]
	a.memory = parameters[1]
	a.threads = parameters[2]
}

func (a *argon2KSF) String() string {
	return fmt.Sprintf(argon2idFormat, argon2ids, a.time, a.memory, a.threads)
}

func (a *argon2KSF) Params() []int {
	return []int{a.time, a.memory, a.threads}
}
