// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

var (
	ErrDeleteCurrentKey = errors.New("cannot delete the current key")
	ErrNoSuchKey        = errors.New("no key exists with that identifier")
)

// GeneratedKey holds the various objects related to a generated JWK.
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

// Alg returns the key algorithm for when using this key to sign or verify.
func (gk *GeneratedKey) Alg() jwa.KeyAlgorithm {
	return gk.alg
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

// WithSigningKey produces the option that includes this key for signing and verifying.
func (gk *GeneratedKey) WithSigningKey(opts ...jwt.Option) jwt.SignEncryptParseOption {
	return jwt.WithKey(
		gk.alg,
		gk.key,
		opts...,
	)
}

// Keys holds the generated keys for signing and verification.
type Keys struct {
	logger *zap.Logger
	random io.Reader

	alg   jwa.KeyAlgorithm
	kty   jwa.KeyType
	bits  int
	curve elliptic.Curve

	lock          sync.RWMutex
	current       *GeneratedKey
	publicSet     jwk.Set
	generatedKeys map[string]*GeneratedKey
	publicSetJWK  []byte
}

// NewKeys creates a new Keys collection for use in signing and verifying JWTs.
// A Keys has exactly one (1) current key at any time.  Keys can be rotated and
// deleted as desired.
func NewKeys(logger *zap.Logger, cli CLI) (keys *Keys, err error) {
	keys = &Keys{
		logger:        logger,
		random:        rand.Reader,
		bits:          cli.KeySize,
		publicSet:     jwk.NewSet(),
		generatedKeys: make(map[string]*GeneratedKey),
	}

	switch {
	case cli.KeyType == "EC" && cli.KeyCurve == "P-256":
		keys.kty = jwa.EC()
		keys.curve = elliptic.P256()
		keys.alg = jwa.ES256()

	case cli.KeyType == "EC" && cli.KeyCurve == "P-384":
		keys.kty = jwa.EC()
		keys.curve = elliptic.P384()
		keys.alg = jwa.ES384()

	case cli.KeyType == "EC" && cli.KeyCurve == "P-521":
		keys.kty = jwa.EC()
		keys.curve = elliptic.P521()
		keys.alg = jwa.ES512()

	case cli.KeyType == "RSA" && cli.KeySize > 0:
		keys.kty = jwa.RSA()
		keys.bits = cli.KeySize
		keys.alg = jwa.RS256()

	default:
		err = fmt.Errorf("unsupported key parameters: type=%s, size=%d, curve=%s", cli.KeyType, cli.KeySize, cli.KeyCurve)
	}

	var initialCurrent *GeneratedKey
	if err == nil {
		initialCurrent, err = keys.newCurrentKey()
	}

	if err == nil {
		keys.current = initialCurrent
		keys.unsafeAddKey(initialCurrent)
	}

	if err == nil {
		keys.logger.Info("initial current key", zap.String("kid", initialCurrent.KID()))
	}

	return
}

// generatedKeyID creates a URL-safe, random kid from the configured
// source of randomness.
func (keys *Keys) generateKeyID() (kid string, err error) {
	var buf [16]byte
	_, err = io.ReadFull(keys.random, buf[:])
	if err == nil {
		kid = base64.RawURLEncoding.EncodeToString(buf[:])
	}

	return
}

// generateRaw generates the raw key, e.g. RSA or EC.  The raw key
// will always be a private key.
func (keys *Keys) generateRaw() (raw any, err error) {
	switch {
	case keys.kty == jwa.RSA():
		raw, err = rsa.GenerateKey(keys.random, keys.bits)

	case keys.kty == jwa.EC():
		raw, err = ecdsa.GenerateKey(keys.curve, keys.random)

	default:
		err = fmt.Errorf("unsupported key type: %s", keys.kty)
	}

	return
}

// newGeneratedKey creates the GeneratedKey metadata that wraps the given raw key.
func (keys *Keys) newGeneratedKey(kid string, raw any) (gk *GeneratedKey, err error) {
	gk = &GeneratedKey{
		alg: keys.alg,
		kid: kid,
	}

	gk.key, err = jwk.Import(raw)

	if err == nil {
		gk.key.Set(jwk.KeyUsageKey, jwk.ForSignature)
		gk.key.Set(jwk.KeyOpsKey, jwk.KeyOperationList{jwk.KeyOpSign, jwk.KeyOpVerify})
		gk.key.Set(jwk.KeyIDKey, kid)
	}

	if err == nil {
		gk.publicKey, err = gk.key.PublicKey()
	}

	if err == nil {
		gk.publicJWK, err = json.Marshal(gk.publicKey)
	}

	return
}

// newCurrentKey is a Template Method that uses the other generation functions
// to create a new GeneratedKey to use as the current signing and verifying key.
// This method does not modify this Keys instance.
func (keys *Keys) newCurrentKey() (gk *GeneratedKey, err error) {
	var (
		kid string
		raw any
	)

	kid, err = keys.generateKeyID()
	if err == nil {
		raw, err = keys.generateRaw()
	}

	if err == nil {
		gk, err = keys.newGeneratedKey(kid, raw)
	}

	return
}

// unsafeAddKey adds the given key to our internal set.  This
// method must either be executed under the lock or in a situation where
// no concurrency is possible, e.g. NewKey.
func (keys *Keys) unsafeAddKey(newKey *GeneratedKey) {
	// TODO: how to handle marshal errors
	keys.generatedKeys[newKey.KID()] = newKey
	keys.publicSet.AddKey(newKey.publicKey)
	keys.publicSetJWK, _ = json.Marshal(keys.publicSet)
}

// Rotate handles creating a new current key and adding it to the set.
// The new current key is returned.
func (keys *Keys) Rotate() (current *GeneratedKey, err error) {
	if current, err = keys.newCurrentKey(); err == nil {
		keys.logger.Info("rotating key", zap.String("kid", current.KID()))

		defer keys.lock.Unlock()
		keys.lock.Lock()

		keys.unsafeAddKey(current)
		keys.current = current
	}

	return
}

// Delete actually removes a key.  This method is idempotent, and no
// error occurs if the key does not exist. In addition, if kid refers to
// the current key, this method does nothing.
func (keys *Keys) Delete(kid string) error {
	defer keys.lock.Unlock()
	keys.lock.Lock()

	if currentKID, ok := keys.current.key.KeyID(); ok && currentKID == kid {
		return ErrDeleteCurrentKey
	}

	gk, exists := keys.generatedKeys[kid]
	if !exists {
		return ErrNoSuchKey
	}

	// TODO: how to handle marshal errors
	keys.logger.Info("removing key", zap.String("kid", kid))
	delete(keys.generatedKeys, kid)
	keys.publicSet.RemoveKey(gk.publicKey)
	keys.publicSetJWK, _ = json.Marshal(keys.publicSet)
	return nil
}

// Get retrieves the GeneratedKey with the given kid.  If no such key exists,
// this method returns nil and false.
func (keys *Keys) Get(kid string) (gk *GeneratedKey, exists bool) {
	keys.lock.RLock()
	gk, exists = keys.generatedKeys[kid]
	keys.lock.RUnlock()

	return
}

// Current returns the key currently being used for signing and verification.
func (keys *Keys) Current() (gk *GeneratedKey) {
	keys.lock.RLock()
	gk = keys.current
	keys.lock.RUnlock()
	return
}

// WriteTo writes all public keys, the current and any waiting to expire,
// in jwk-set format to the given writer.
func (keys *Keys) WriteTo(dst io.Writer) (int64, error) {
	keys.lock.RLock()
	n, err := dst.Write(keys.publicSetJWK)
	keys.lock.RUnlock()

	return int64(n), err
}

// KeyHandler renders PUBLIC keys over HTTP.
type KeyHandler struct {
	logger *zap.Logger
	keys   *Keys
}

func NewKeyHandler(logger *zap.Logger, key *Keys) *KeyHandler {
	return &KeyHandler{
		logger: logger,
		keys:   key,
	}
}

func (kh *KeyHandler) writeKey(response http.ResponseWriter, key *GeneratedKey) {
	response.Header().Set("Content-Type", "application/jwk+json")
	key.WriteTo(response)
}

// ServeHTTP serves up the JWK format of generated keys.
func (kh *KeyHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if kid := request.PathValue("kid"); len(kid) > 0 {
		if key, exists := kh.keys.Get(kid); exists {
			kh.writeKey(response, key)
		} else {
			response.WriteHeader(http.StatusNotFound)
		}
	} else {
		kh.writeKey(response, kh.keys.Current())
	}
}

// KeysHandlers serves up the set of all keys in a Keys.
type KeysHandler struct {
	logger *zap.Logger
	keys   *Keys
}

func NewKeysHandler(l *zap.Logger, keys *Keys) *KeysHandler {
	return &KeysHandler{
		logger: l,
		keys:   keys,
	}
}

// ServeHTTP serves up the JWK key set in jwk-set format.
func (kh *KeysHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/jwk-set+json")
	kh.keys.WriteTo(response)
}

func ProvideKey() fx.Option {
	return fx.Provide(
		NewKeys,
		NewKeyHandler,
		NewKeysHandler,
	)
}
