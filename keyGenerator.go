// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"go.uber.org/fx"
)

// GeneratedKey holds the various objects related to a generated JWK. Instances
// of this type are immutable once created.
type GeneratedKey struct {
	// alg is the key algorithm to use when signing and verifying.
	// This will vary according to the type of key.
	alg jwa.KeyAlgorithm

	// kid is the unique key identifier for this key.  This will
	// be used as the jti for generated JWTs.
	kid string

	// key is the actual generated key.  This will always be a PRIVATE key.
	key jwk.Key

	// publicKey is the public portion of key.
	publicKey jwk.Key

	// publicJWK holds the premarshaled public key material for this key.
	publicJWK []byte
}

// KID returns the unique key identifier for this key.
func (gk *GeneratedKey) KID() string {
	return gk.kid
}

// WriteTo writes the public portion of this key to an arbitrary writer.
// The key will be in jwk+json format.
func (gk *GeneratedKey) WriteTo(dst io.Writer) (int64, error) {
	n, err := dst.Write(gk.publicJWK)
	return int64(n), err
}

// KeyGenerator generates raw keys, e.g. EC and RSA.
type KeyGenerator struct {
	random      io.Reader
	idGenerator *IDGenerator
	alg         jwa.KeyAlgorithm
	ec          bool
	bits        int
	curve       elliptic.Curve
}

func NewKeyGenerator(idGenerator *IDGenerator, cli CLI) (kg *KeyGenerator, err error) {
	kg = &KeyGenerator{
		random:      rand.Reader,
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
func (kg *KeyGenerator) Generate() (gk *GeneratedKey, err error) {
	gk = &GeneratedKey{
		alg: kg.alg,
		kid: kg.idGenerator.Generate(16),
	}

	var raw any
	raw, err = kg.generateRaw()
	if err == nil {
		gk.key, err = jwk.Import(raw)
	}

	if err == nil {
		gk.key.Set(jwk.KeyUsageKey, jwk.ForSignature)
		gk.key.Set(jwk.KeyOpsKey, jwk.KeyOperationList{jwk.KeyOpSign, jwk.KeyOpVerify})
		gk.key.Set(jwk.KeyIDKey, gk.kid)
	}

	if err == nil {
		gk.publicKey, err = gk.key.PublicKey()
	}

	if err == nil {
		gk.publicJWK, err = json.Marshal(gk.publicKey)
	}

	return
}

func ProvideKeyGenerator() fx.Option {
	return fx.Provide(
		NewKeyGenerator,
	)
}
