// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"crypto"
	"crypto/rand"
	"io"
	"math/big"
	"time"

	"golang.org/x/crypto/openpgp/internal/algorithm"
	"golang.org/x/crypto/openpgp/s2k"
)

// Config collects a number of parameters along with sensible defaults.
// A nil *Config is valid and results in all default values.
type Config struct {
	// Rand provides the source of entropy.
	// If nil, the crypto/rand Reader is used.
	Rand io.Reader
	// DefaultHash is the default hash function to be used.
	// If zero, SHA-256 is used.
	DefaultHash     crypto.Hash
	HashPreferences []uint8
	// DefaultCipher is the cipher to be used.
	// If zero, AES-128 is used.
	DefaultCipher     CipherFunction
	CipherPreferences []uint8
	// Time returns the current time as the number of seconds since the
	// epoch. If Time is nil, time.Now is used.
	Time func() time.Time
	// DefaultCompressionAlgo is the compression algorithm to be
	// applied to the plaintext before encryption. If zero, no
	// compression is done.
	DefaultCompressionAlgo CompressionAlgo
	// CompressionConfig configures the compression settings.
	CompressionConfig *CompressionConfig
	// S2KCount is only used for symmetric encryption. It
	// determines the strength of the passphrase stretching when
	// the said passphrase is hashed to produce a key. S2KCount
	// should be between 1024 and 65011712, inclusive. If Config
	// is nil or S2KCount is 0, the value 65536 used. Not all
	// values in the above range can be represented. S2KCount will
	// be rounded up to the next representable value if it cannot
	// be encoded exactly. When set, it is strongly encrouraged to
	// use a value that is at least 65536. See RFC 4880 Section
	// 3.7.1.3.
	S2KCount int
	// RSABits is the number of bits in new RSA keys made with NewEntity.
	// If zero, then 2048 bit keys are created.
	RSABits int
	// The public key algorithm to use - will always create a signing primary
	// key and encryption subkey.
	Algorithm PublicKeyAlgorithm
	// Some known primes that are optionally prepopulated by the caller
	RSAPrimes []*big.Int
	// AEADConfig configures the use of the new AEAD Encrypted Data Packet,
	// defined in the draft of the next version of the OpenPGP specification.
	// If a non-nil AEADConfig is passed, usage of this packet is enabled. By
	// default, it is disabled. See the documentation of AEADConfig for more
	// configuration options related to AEAD.
	// **Note: using this option may break compatibility with other OpenPGP
	// implementations, as well as future versions of this library.**
	AEADConfig *AEADConfig
}

func (c *Config) Random() io.Reader {
	if c == nil || c.Rand == nil {
		return rand.Reader
	}
	return c.Rand
}

func (c *Config) Hash() crypto.Hash {
	if c == nil || uint(c.DefaultHash) == 0 {
		return crypto.SHA256
	}
	return c.DefaultHash
}

func (c *Config) PreferredHashAlgorithms() []uint8 {
	return c.sanitizedHashPreferences()
}

func (c *Config) Cipher() CipherFunction {
	if c == nil || uint8(c.DefaultCipher) == 0 {
		return CipherAES128
	}
	return c.DefaultCipher
}

func (c *Config) PreferredSymmetricAlgorithms() []uint8 {
	return c.sanitizedCipherPreferences()
}

func (c *Config) Now() time.Time {
	if c == nil || c.Time == nil {
		return time.Now()
	}
	return c.Time()
}

func (c *Config) Compression() CompressionAlgo {
	if c == nil {
		return CompressionNone
	}
	return c.DefaultCompressionAlgo
}

func (c *Config) PasswordHashIterations() int {
	if c == nil || c.S2KCount == 0 {
		return 0
	}
	return c.S2KCount
}

func (c *Config) RSAModulusBits() int {
	if c == nil || c.RSABits == 0 {
		return 2048
	}
	return c.RSABits
}

func (c *Config) PublicKeyAlgorithm() PublicKeyAlgorithm {
	if c == nil || c.Algorithm == 0 {
		return PubKeyAlgoRSA
	}
	return c.Algorithm
}

func (c *Config) AEAD() *AEADConfig {
	if c == nil {
		return nil
	}
	return c.AEADConfig
}

// Ensures that the default cipher is included, and removes unsupported
// algorithms.
func (c *Config) sanitizedCipherPreferences() []uint8 {
	mustId:= algorithm.AES128.Id()
	if c == nil {
		return []uint8{mustId}
	}
	if c.DefaultCipher != 0 {
		c.CipherPreferences = []uint8{uint8(c.DefaultCipher)}
	}
	sanitized := make([]uint8, 0)
	mustPresent := false
	for _, id := range c.CipherPreferences {
		cipher, ok := algorithm.CipherById[id]
		if ok {
			sanitized = append(sanitized, id)
		}
		if cipher.Id() == mustId {
			mustPresent = true
		}
	}
	if !mustPresent {
		sanitized = append(sanitized, mustId)
	}
	return sanitized
}

// Ensures that the default hash is included and removes unsupported hashes.
func (c *Config) sanitizedHashPreferences() []uint8 {
	mustId, _ := s2k.HashToHashId(crypto.SHA256)
	if c == nil {
		return []uint8{mustId}
	}
	if c.DefaultHash != 0 {
		id, ok := s2k.HashToHashId(c.DefaultHash)
		if ok {
			c.HashPreferences = []uint8{id}
		}
	}
	sanitized := make([]uint8, 0)
	mustPresent := false
	for _, id := range c.HashPreferences {
		_, ok := algorithm.HashById[id]
		if ok {
			sanitized = append(sanitized, id)
		}
		if id == mustId {
			mustPresent = true
		}
	}
	if !mustPresent {
		sanitized = append(sanitized, mustId)
	}
	return sanitized
}
