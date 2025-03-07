// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"encoding/base64"
	"io"

	"go.uber.org/fx"
)

// IDGenerator handles generating unique, URL-safe identifiers.
type IDGenerator struct {
	random io.Reader
}

// Generate generates an identifier with the original number of random bytes.
// The returned string will be encoded as a URL-safe base64 string.
func (idg *IDGenerator) Generate(size int) string {
	raw := make([]byte, size)
	io.ReadFull(idg.random, raw)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func NewIDGenerator() *IDGenerator {
	return &IDGenerator{
		random: rand.Reader,
	}
}

func ProvideIDGenerator() fx.Option {
	return fx.Provide(
		NewIDGenerator,
	)
}
