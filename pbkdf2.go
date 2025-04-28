// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ksf

import (
	"crypto/sha512"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

const (
	defaultPBKDF2iterations = 10000
	pbkdf2s                 = "PBKDF2"
	pbkdf2Format            = "%s(%d-SHA512)"
)

type pbkdf2KSF struct {
	iterations int
}

func pbkdf2New() *pbkdf2KSF {
	return &pbkdf2KSF{
		iterations: defaultPBKDF2iterations,
	}
}

func (p *pbkdf2KSF) Harden(password, salt []byte, length int) []byte {
	return pbkdf2.Key(password, salt, p.iterations, length, sha512.New)
}

// Parameterize replaces the functions parameters with the new ones. Must match the amount of parameters.
func (p *pbkdf2KSF) Parameterize(parameters ...int) {
	if len(parameters) != 1 {
		panic(errParams)
	}

	p.iterations = parameters[0]
}

func (p *pbkdf2KSF) String() string {
	return fmt.Sprintf(pbkdf2Format, pbkdf2s, p.iterations)
}

func (p *pbkdf2KSF) Params() []int {
	return []int{p.iterations}
}
