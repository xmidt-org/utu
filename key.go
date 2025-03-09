// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Key represents a signing and/or verification key.
type Key struct {
	KID     string
	Alg     jwa.KeyAlgorithm
	Key     jwk.Key
	Created time.Time
	Expires time.Time
}

// PublicKey produces a Key that represents only public key material.
// All other fields, such as the KID, are copied over as is.
//
// This method should generally be used prior to storing a Key in
// a KeyStore.
func (k Key) PublicKey() (pk Key, err error) {
	pk = k
	var public jwk.Key
	public, err = k.Key.PublicKey()
	if err == nil {
		pk.Key = public
	}

	return
}

// WriteTo writes the PUBLIC portion of this key to the given writer
// in JWK format.
func (k Key) WriteTo(dst io.Writer) (n int64, err error) {
	var (
		public jwk.Key
		data   []byte
	)

	public, err = k.Key.PublicKey()
	if err == nil {
		data, err = json.Marshal(public)
	}

	if err == nil {
		var c int
		c, err = dst.Write(data)
		n = int64(c)
	}

	return
}

// NewPublicSet creates a JWK key set using only public key material.
func NewPublicSet(keys ...Key) (set jwk.Set, err error) {
	set = jwk.NewSet()
	for i := 0; err == nil && i < len(keys); i++ {
		var pk jwk.Key
		if pk, err = keys[i].Key.PublicKey(); err == nil {
			err = set.AddKey(pk)
		}
	}

	return
}
