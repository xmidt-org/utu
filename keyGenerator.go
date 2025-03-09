// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"go.uber.org/fx"
)

// KeyGenerator generates raw keys, e.g. EC and RSA.
//
// A KeyGenerator sets an expires on all keys. The expires value
// for keys is <key rotation> + <token expires> + <1 minute grace>.
// This allows for tokens signed by rotated keys to be validated
// until they expire.
type KeyGenerator struct {
	random      io.Reader
	now         func() time.Time
	expires     time.Duration
	idGenerator *IDGenerator
	alg         jwa.KeyAlgorithm
	ec          bool
	bits        int
	curve       elliptic.Curve
}

func NewKeyGenerator(idGenerator *IDGenerator, cli CLI) (kg *KeyGenerator, err error) {
	kg = &KeyGenerator{
		random:      rand.Reader,
		now:         time.Now,
		expires:     cli.KeyRotate + cli.Expires + time.Minute,
		idGenerator: idGenerator,
	}

	switch {
	case cli.KeyType == "EC" && cli.KeyCurve == "P-256":
		kg.ec = true
		kg.curve = elliptic.P256()
		kg.alg = jwa.ES256()

	case cli.KeyType == "EC" && cli.KeyCurve == "P-384":
		kg.ec = true
		kg.curve = elliptic.P384()
		kg.alg = jwa.ES384()

	case cli.KeyType == "EC" && cli.KeyCurve == "P-521":
		kg.ec = true
		kg.curve = elliptic.P521()
		kg.alg = jwa.ES512()

	case cli.KeyType == "RSA" && cli.KeySize > 0:
		kg.ec = false
		kg.bits = cli.KeySize
		kg.alg = jwa.RS256()

	default:
		err = fmt.Errorf("unsupported key parameters: type=%s, size=%d, curve=%s", cli.KeyType, cli.KeySize, cli.KeyCurve)
	}

	return
}

// generateRaw generates the raw key appropriate for this instance's configuration.
func (kg *KeyGenerator) generateRaw() (raw any, err error) {
	// TODO: support other kinds of keys
	switch {
	case kg.ec:
		raw, err = ecdsa.GenerateKey(kg.curve, kg.random)

	default:
		raw, err = rsa.GenerateKey(kg.random, kg.bits)
	}

	return
}

// Generate creates a new, random key appropriate for signing and verification.
func (kg *KeyGenerator) Generate() (k Key, err error) {
	k = Key{
		KID: kg.idGenerator.Generate(16),
		Alg: kg.alg,
	}

	var raw any
	raw, err = kg.generateRaw()
	if err == nil {
		k.Key, err = jwk.Import(raw)
	}

	if err == nil {
		k.Created = kg.now().UTC()
		k.Expires = k.Created.Add(kg.expires)
		k.Key.Set(jwk.KeyUsageKey, jwk.ForSignature)
		k.Key.Set(jwk.KeyOpsKey, jwk.KeyOperationList{jwk.KeyOpSign, jwk.KeyOpVerify})
		k.Key.Set(jwk.KeyIDKey, k.KID)
	}

	return
}

func ProvideKeyGenerator() fx.Option {
	return fx.Provide(
		NewKeyGenerator,
	)
}
