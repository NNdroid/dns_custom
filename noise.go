package dnstunnel

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"sync"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// NoiseKeyPair represents a Curve25519 public/private keypair
type NoiseKeyPair struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

// GenerateNoiseKeyPair generates a random Curve25519 keypair
func GenerateNoiseKeyPair() (*NoiseKeyPair, error) {
	var kp NoiseKeyPair
	if _, err := rand.Read(kp.PrivateKey[:]); err != nil {
		return nil, err
	}
	// Clamp private key
	kp.PrivateKey[0] &= 248
	kp.PrivateKey[31] &= 127
	kp.PrivateKey[31] |= 64

	pub, err := curve25519.X25519(kp.PrivateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(kp.PublicKey[:], pub)
	return &kp, nil
}

// ParseNoiseKey parses a 32-byte key from hex or base64 string
func ParseNoiseKey(s string) ([32]byte, error) {
	var key [32]byte
	s = strings.TrimSpace(s)
	if len(s) == 64 {
		b, err := hex.DecodeString(s)
		if err == nil && len(b) == 32 {
			copy(key[:], b)
			return key, nil
		}
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err == nil && len(b) == 32 {
		copy(key[:], b)
		return key, nil
	}
	b, err = base64.RawStdEncoding.DecodeString(s)
	if err == nil && len(b) == 32 {
		copy(key[:], b)
		return key, nil
	}
	return key, fmt.Errorf("invalid key format (expected 64 hex chars or 32-byte base64)")
}

// FormatNoiseKey formats a 32-byte key to hex and base64
func FormatNoiseKey(key [32]byte) (hexStr, b64Str string) {
	return hex.EncodeToString(key[:]), base64.StdEncoding.EncodeToString(key[:])
}

// noiseTagSize is the AEAD authentication tag appended to every sealed payload.
const noiseTagSize = chacha20poly1305.Overhead

// NoiseCipherState wraps the AEAD derived from a Noise_NK handshake.
//
// The nonce is NOT a stream counter: it is supplied explicitly by the caller and
// is derived from the transport sequence number (upstream = dataSeq, downstream =
// serverSeq). An auto-incrementing nonce implicitly assumes one encryption per
// successful delivery in both directions, which DNS cannot provide - queries and
// answers are lost, duplicated, reordered and retransmitted. With a sequence-derived
// nonce every message is self-describing: it can arrive any number of times, in any
// order, and still decrypt, which is exactly what the reliability layer needs.
type NoiseCipherState struct {
	aead cipher.AEAD
}

func newNoiseCipherState(key []byte) (*NoiseCipherState, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &NoiseCipherState{aead: aead}, nil
}

// noiseNoncePool reuses the 12-byte nonce buffers. The nonce has to live in a
// heap cell because Seal/Open are reached through the cipher.AEAD interface,
// which defeats escape analysis; a pool beats one small allocation per message
// on both data paths. Seal/Open are synchronous and never retain the nonce, so
// the buffer can be recycled as soon as they return.
var noiseNoncePool = sync.Pool{New: func() any { return new([12]byte) }}

// noiseNonce writes the 12-byte AEAD nonce derived from seq into buf.
func noiseNonce(buf *[12]byte, seq uint64) {
	binary.LittleEndian.PutUint64(buf[4:], seq)
}

// Encrypt seals plaintext under the nonce derived from seq. Same seq + same
// plaintext always yields the same ciphertext, so retransmissions are byte-identical.
func (s *NoiseCipherState) Encrypt(seq uint64, plaintext []byte) []byte {
	n := noiseNoncePool.Get().(*[12]byte)
	noiseNonce(n, seq)
	ct := s.aead.Seal(nil, n[:], plaintext, nil)
	noiseNoncePool.Put(n)
	return ct
}

// Decrypt opens ciphertext using the nonce derived from seq.
func (s *NoiseCipherState) Decrypt(seq uint64, ciphertext []byte) ([]byte, error) {
	n := noiseNoncePool.Get().(*[12]byte)
	noiseNonce(n, seq)
	plain, err := s.aead.Open(nil, n[:], ciphertext, nil)
	noiseNoncePool.Put(n)
	return plain, err
}

// NoiseSession manages bidirectional encrypted channel derived from Noise_NK handshake
type NoiseSession struct {
	SendCipher *NoiseCipherState
	RecvCipher *NoiseCipherState
}

func blake2sHash() hash.Hash {
	h, _ := blake2s.New256(nil)
	return h
}

// NewClientNoiseSession initiates Noise_NK handshake against server public key
// Returns (NoiseSession, clientEphemeralPubkeyBytes, error)
func NewClientNoiseSession(serverPubkey [32]byte) (*NoiseSession, []byte, error) {
	var ePriv [32]byte
	if _, err := rand.Read(ePriv[:]); err != nil {
		return nil, nil, err
	}
	ePriv[0] &= 248
	ePriv[31] &= 127
	ePriv[31] |= 64

	ePub, err := curve25519.X25519(ePriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	dh, err := curve25519.X25519(ePriv[:], serverPubkey[:])
	if err != nil {
		return nil, nil, err
	}

	// The KDF binds the DH output with the server's static public key as salt.
	// A full Noise_NK handshake would also chain the transcript hash (including
	// the client ephemeral) through blake2s into this derivation; the binding
	// is deliberately NOT changed here because the wire handshake is shared
	// with the deployed Stun Android/TV clients, whose implementation this
	// repository does not control - changing the salt would break every
	// deployed client against a new server. The DH output already guarantees
	// per-session key uniqueness, so the omission costs transcript-binding
	// hygiene, not confidentiality.
	kdf := hkdf.New(blake2sHash, dh, serverPubkey[:], []byte("dns_custom_noise_v1"))
	kC2S := make([]byte, 32)
	kS2C := make([]byte, 32)
	if _, err := io.ReadFull(kdf, kC2S); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(kdf, kS2C); err != nil {
		return nil, nil, err
	}

	sendCipher, err := newNoiseCipherState(kC2S)
	if err != nil {
		return nil, nil, err
	}
	recvCipher, err := newNoiseCipherState(kS2C)
	if err != nil {
		return nil, nil, err
	}

	return &NoiseSession{SendCipher: sendCipher, RecvCipher: recvCipher}, ePub, nil
}

// NewServerNoiseSession derives keys on server side using server static private key and client ephemeral public key
func NewServerNoiseSession(serverPrivkey [32]byte, clientEPub []byte) (*NoiseSession, error) {
	if len(clientEPub) != 32 {
		return nil, errors.New("invalid client ephemeral pubkey length")
	}
	serverPub, err := curve25519.X25519(serverPrivkey[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	dh, err := curve25519.X25519(serverPrivkey[:], clientEPub)
	if err != nil {
		return nil, err
	}

	kdf := hkdf.New(blake2sHash, dh, serverPub, []byte("dns_custom_noise_v1"))
	kC2S := make([]byte, 32)
	kS2C := make([]byte, 32)
	if _, err := io.ReadFull(kdf, kC2S); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(kdf, kS2C); err != nil {
		return nil, err
	}

	recvCipher, err := newNoiseCipherState(kC2S)
	if err != nil {
		return nil, err
	}
	sendCipher, err := newNoiseCipherState(kS2C)
	if err != nil {
		return nil, err
	}

	return &NoiseSession{SendCipher: sendCipher, RecvCipher: recvCipher}, nil
}
