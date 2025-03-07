// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

var (
	ErrDeleteCurrentKey = errors.New("cannot delete the current key")
	ErrNoSuchKey        = errors.New("no key exists with that identifier")
)

// Keys is a manager for signing and verification keys.  Exactly (1) current key
// is exposed for signing JWTs, with a number of other keys kept in escrow as
// rotation happens.
type Keys struct {
	logger       *zap.Logger
	keyGenerator *KeyGenerator

	lock          sync.RWMutex
	current       *GeneratedKey
	publicSet     jwk.Set
	generatedKeys map[string]*GeneratedKey
	publicSetJWK  []byte
}

// NewKeys creates a new Keys collection for use in signing and verifying JWTs.
// A Keys has exactly one (1) current key at any time.  Keys can be rotated and
// deleted as desired.
func NewKeys(logger *zap.Logger, keyGenerator *KeyGenerator, cli CLI) (keys *Keys, err error) {
	keys = &Keys{
		logger:        logger,
		keyGenerator:  keyGenerator,
		publicSet:     jwk.NewSet(),
		generatedKeys: make(map[string]*GeneratedKey),
	}

	var initialCurrent *GeneratedKey
	if err == nil {
		initialCurrent, err = keys.keyGenerator.Generate()
	}

	if err == nil {
		keys.current = initialCurrent
		keys.unsafeAddKey(initialCurrent)
	}

	if err == nil {
		keys.logger.Info("keys", Key("initial", keys.current))
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
	if current, err = keys.keyGenerator.Generate(); err == nil {
		keys.logger.Info("rotating key", Key("new current", current))

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
	keys.logger.Info("removing key", Key("key", gk))
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

func ProvideKeys() fx.Option {
	return fx.Provide(
		NewKeys,
		NewKeyHandler,
		NewKeysHandler,
	)
}
