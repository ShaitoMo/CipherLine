// netio.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/crypto/hkdf"
)

const (
	headerSize      = 4
	nonceSize       = 12 // AES-GCM nonce
	helloNonceSize  = 16 // handshake nonce
	x25519PubSize   = 32
	hmacSize        = 32
	maxFrameDefault = 64 * 1024
)

// --- Legacy static AES key (proof only; NOT used) ---
// var staticKey = mustHex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

// PSK used ONLY to authenticate the handshake transcript (MITM protection).
// Loaded at startup from the CHAT_PSK environment variable — must match the
// server's (see loadPSK below and CHAT_PSK in server's main()).
var handshakePSK []byte

// loadPSK reads CHAT_PSK (a 64-character hex string, i.e. 32 bytes) from the
// environment. Call this once before any handshake.
func loadPSK() error {
	hexKey := os.Getenv("CHAT_PSK")
	if hexKey == "" {
		return fmt.Errorf("CHAT_PSK environment variable is not set (generate one with: openssl rand -hex 32)")
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return fmt.Errorf("CHAT_PSK is not valid hex: %w", err)
	}
	if len(key) != 32 {
		return fmt.Errorf("CHAT_PSK must decode to 32 bytes, got %d", len(key))
	}
	handshakePSK = key
	return nil
}

type SecureConn struct {
	conn net.Conn
	key  []byte // 32 bytes AES-256-GCM session key
}

func NewSecureConn(conn net.Conn, key []byte) *SecureConn {
	k := make([]byte, 32)
	copy(k, key[:32])
	return &SecureConn{conn: conn, key: k}
}

func (sc *SecureConn) Close() error { return sc.conn.Close() }

// Encrypted frame:
// wire = [u32_be payload_len][ payload = nonce(12) || ciphertext+tag ]
//
// Nonces are random (96-bit) rather than a counter. Per NIST SP 800-38D, the
// collision risk for random nonces under one key becomes non-negligible
// around ~2^32 messages -- comfortably above what this chat's usage
// produces per session, but a long-lived, high-throughput connection should
// switch to a counter-based nonce instead.
func (sc *SecureConn) SendFrame(plaintext []byte) error {
	block, err := aes.NewCipher(sc.key)
	if err != nil {
		return fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}

	// gcm.Seal returns ciphertext||tag
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	payload := append(nonce, ciphertext...)

	hdr := make([]byte, headerSize)
	binary.BigEndian.PutUint32(hdr, uint32(len(payload)))

	if err := writeAll(sc.conn, hdr); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if err := writeAll(sc.conn, payload); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	return nil
}

func (sc *SecureConn) RecvFrame(maxMsg uint32) ([]byte, error) {
	hdr := make([]byte, headerSize)
	if _, err := io.ReadFull(sc.conn, hdr); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	n := binary.BigEndian.Uint32(hdr)
	if n > maxMsg {
		return nil, fmt.Errorf("frame too large: %d > %d", n, maxMsg)
	}
	if n < nonceSize {
		return nil, fmt.Errorf("bad frame: too small")
	}

	payload := make([]byte, n)
	if _, err := io.ReadFull(sc.conn, payload); err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}

	nonce := payload[:nonceSize]
	ciphertext := payload[nonceSize:]

	block, err := aes.NewCipher(sc.key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt/auth failed: %w", err)
	}
	return plaintext, nil
}

// ---------------- Handshake (MITM-resistant AKE) ----------------
//
// ClientHello: "HS1C"||Cpub(32)||Cn(16)
// ServerHello: "HS1S"||Spub(32)||Sn(16)||Smac(32)
// ClientAuth : "HS1A"||Cmac(32)
//
// transcript = "HS1"||Cpub||Spub||Cn||Sn
// Smac/Cmac = HMAC-SHA256(PSK, transcript)
//
// session_key = HKDF-SHA256(shared_secret, salt=Cn||Sn, info="chat-aesgcm-v1", 32 bytes)
//
func HandshakeClient(conn net.Conn) (*SecureConn, error) {
	curve := ecdh.X25519()

	// Ephemeral client keypair
	cpriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("x25519 keygen: %w", err)
	}
	Cpub := cpriv.PublicKey().Bytes() // 32 bytes

	Cn := make([]byte, helloNonceSize)
	if _, err := rand.Read(Cn); err != nil {
		return nil, fmt.Errorf("client nonce: %w", err)
	}

	// Send ClientHello
	if err := writeAll(conn, []byte("HS1C")); err != nil {
		return nil, fmt.Errorf("send HS1C: %w", err)
	}
	if err := writeAll(conn, Cpub); err != nil {
		return nil, fmt.Errorf("send Cpub: %w", err)
	}
	if err := writeAll(conn, Cn); err != nil {
		return nil, fmt.Errorf("send Cn: %w", err)
	}

	// Receive ServerHello
	mS := make([]byte, 4)
	if _, err := io.ReadFull(conn, mS); err != nil {
		return nil, fmt.Errorf("read HS1S: %w", err)
	}
	if string(mS) != "HS1S" {
		return nil, fmt.Errorf("bad ServerHello magic: %q", string(mS))
	}

	Spub := make([]byte, x25519PubSize)
	Sn := make([]byte, helloNonceSize)
	Smac := make([]byte, hmacSize)

	if _, err := io.ReadFull(conn, Spub); err != nil {
		return nil, fmt.Errorf("read Spub: %w", err)
	}
	if _, err := io.ReadFull(conn, Sn); err != nil {
		return nil, fmt.Errorf("read Sn: %w", err)
	}
	if _, err := io.ReadFull(conn, Smac); err != nil {
		return nil, fmt.Errorf("read Smac: %w", err)
	}

	// Verify Smac
	transcript := buildTranscript(Cpub, Spub, Cn, Sn)
	expSmac := hmacSHA256(handshakePSK, transcript)
	if !hmac.Equal(Smac, expSmac) {
		return nil, fmt.Errorf("server auth failed (MITM or wrong PSK)")
	}

	// Shared secret
	spubKey, err := curve.NewPublicKey(Spub)
	if err != nil {
		return nil, fmt.Errorf("server pub parse: %w", err)
	}
	shared, err := cpriv.ECDH(spubKey)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}

	// Derive session key
	sessionKey, err := deriveSessionKey(shared, Cn, Sn)
	if err != nil {
		return nil, err
	}

	// Send ClientAuth
	Cmac := hmacSHA256(handshakePSK, transcript)
	if err := writeAll(conn, []byte("HS1A")); err != nil {
		return nil, fmt.Errorf("send HS1A: %w", err)
	}
	if err := writeAll(conn, Cmac); err != nil {
		return nil, fmt.Errorf("send Cmac: %w", err)
	}

	return NewSecureConn(conn, sessionKey), nil
}

func buildTranscript(Cpub, Spub, Cn, Sn []byte) []byte {
	// "HS1"||Cpub||Spub||Cn||Sn
	t := make([]byte, 0, 3+32+32+16+16)
	t = append(t, 'H', 'S', '1')
	t = append(t, Cpub...)
	t = append(t, Spub...)
	t = append(t, Cn...)
	t = append(t, Sn...)
	return t
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil) // 32 bytes
}

func deriveSessionKey(shared, Cn, Sn []byte) ([]byte, error) {
	salt := append(append([]byte{}, Cn...), Sn...) // Cn||Sn
	info := []byte("chat-aesgcm-v1")

	r := hkdf.New(sha256.New, shared, salt, info)
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return out, nil
}

// ---------------- Utilities ----------------
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
