// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openpgp

import (
	"math/big"
	"time"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/openpgp/ecdh"
	"golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/internal/algorithm"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/rsa"
)

type keyPair struct {
	pub  *packet.PublicKey
	priv *packet.PrivateKey
}

// NewEntity returns an Entity that contains a fresh RSA/RSA keypair with a
// single identity composed of the given full name, comment and email, any of
// which may be empty but must not contain any of "()<>\x00".
// If config is nil, sensible defaults will be used.
func NewEntity(name, comment, email string, config *packet.Config) (*Entity, error) {
	creationTime := config.Now()

	uid := packet.NewUserId(name, comment, email)
	if uid == nil {
		return nil, errors.InvalidArgumentError("user id field contained invalid characters")
	}

	// Generate a primary key with one subkey
	var primary, sub *keyPair
	var err error

	switch config.PublicKeyAlgorithm() {
	case packet.PubKeyAlgoRSA:
		primary, sub, err = rsaGen(config, creationTime)
	case packet.PubKeyAlgoEdDSA:
		primary, sub, err = eddsaGen(config, creationTime)
	default:
		return nil, errors.InvalidArgumentError("unsupported public key algorithm")
	}
	if err != nil {
		return nil, err
	}

	subKey := Subkey{
		PublicKey:  sub.pub,
		PrivateKey: sub.priv,
		Sig: &packet.Signature{
			CreationTime:              creationTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                config.PublicKeyAlgorithm(),
			Hash:                      config.Hash(),
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &primary.pub.KeyId,
		},
	}

	// Binding signatures
	err = subKey.Sig.SignKey(subKey.PublicKey, primary.priv, config)
	if err != nil {
		return nil, err
	}
	isPrimaryId := true
	selfSignature := &packet.Signature{
		SigType:            packet.SigTypePositiveCert,
		PubKeyAlgo:         config.PublicKeyAlgorithm(),
		Hash:               config.Hash(),
		CreationTime:       creationTime,
		PreferredSymmetric: config.PreferredSymmetricAlgorithms(),
		PreferredHash:      config.PreferredHashAlgorithms(),
		PreferredAEAD:      config.AEAD().PreferredAEADModes(),
		IssuerKeyId:        &primary.pub.KeyId,
		IsPrimaryId:        &isPrimaryId,
		FlagsValid:         true,
		FlagSign:           true,
		FlagCertify:        true,
		MDC:                true, // true by default, see 5.8 vs. 5.14
		AEAD:               config.AEAD() != nil,
	}
	err = selfSignature.SignUserId(uid.Id, primary.pub, primary.priv, config)
	if err != nil {
		return nil, err
	}

	return &Entity{
		PrimaryKey: primary.pub,
		PrivateKey: primary.priv,
		Subkeys: []Subkey{subKey},
		Identities: map[string]*Identity{
			uid.Id: &Identity{
				Name:          uid.Id,
				UserId:        uid,
				SelfSignature: selfSignature,
				Signatures:    []*packet.Signature{selfSignature},
			},
		},
	}, nil
}

// Generates a primary key and a subkey with RSA and the given config.
func rsaGen(config *packet.Config, creationTime time.Time) (primary *keyPair, sub *keyPair, err error) {
	bits := config.RSAModulusBits()
	var primaryPrimes []*big.Int
	if config != nil && len(config.RSAPrimes) >= 2 {
		primaryPrimes = config.RSAPrimes[0:2]
	}
	primaryPrivRaw, err := rsa.GenerateKeyWithPrimes(config.Random(), bits, primaryPrimes)
	if err != nil {
		return nil, nil, err
	}
	primary = &keyPair{
		priv: packet.NewRSAPrivateKey(creationTime, primaryPrivRaw),
		pub:  packet.NewRSAPublicKey(creationTime, &primaryPrivRaw.PublicKey),
	}

	var subkeyPrimes []*big.Int
	if config != nil && len(config.RSAPrimes) >= 4 {
		subkeyPrimes = config.RSAPrimes[2:4]
	}
	subPrivRaw, err := rsa.GenerateKeyWithPrimes(config.Random(), bits, subkeyPrimes)
	if err != nil {
		return nil, nil, err
	}
	sub = &keyPair{
		pub:  packet.NewRSAPublicKey(creationTime, &subPrivRaw.PublicKey),
		priv: packet.NewRSAPrivateKey(creationTime, subPrivRaw),
	}
	sub.pub.IsSubkey = true
	sub.priv.IsSubkey = true
	return
}

// Generates a primary key and a subkey with EdDSA and the given config.
func eddsaGen(config *packet.Config, creationTime time.Time) (primary *keyPair, sub *keyPair, err error) {
	primaryPubRaw, primaryPrivRaw, err := ed25519.GenerateKey(config.Random())
	if err != nil {
		return nil, nil, err
	}
	primary = &keyPair{
		pub:  packet.NewEdDSAPublicKey(creationTime, primaryPubRaw),
		priv: packet.NewEdDSAPrivateKey(creationTime, primaryPrivRaw),
	}

	var kdf = ecdh.KDF{
		Hash:   algorithm.SHA512,
		Cipher: algorithm.AES256,
	}
	subPrivRaw, err := ecdh.X25519GenerateKey(config.Random(), kdf)
	if err != nil {
		return nil, nil, err
	}
	sub = &keyPair{
		pub:  packet.NewECDHPublicKey(creationTime, &subPrivRaw.PublicKey),
		priv: packet.NewECDHPrivateKey(creationTime, subPrivRaw),
	}
	sub.pub.IsSubkey = true
	sub.priv.IsSubkey = true
	return
}
