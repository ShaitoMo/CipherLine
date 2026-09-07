// net_io.cpp
#include "net_io.h"

#include <array>
#include <cstring>
#include <iostream>
#include <mutex>
#include <unordered_map>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

static constexpr int NONCE_SIZE = 12;
static constexpr int TAG_SIZE   = 16;
static constexpr int HELLO_NONCE_SIZE = 16;
static constexpr int X25519_PUB_SIZE  = 32;
static constexpr int HMAC_SIZE        = 32;

// --- Legacy (static AES key) kept only as proof; NOT used ---
// static const uint8_t STATIC_AES_GCM_KEY[32] = { ... };

// PSK is only for authenticating the handshake transcript (MITM protection).
// Loaded at startup from the CHAT_PSK env var via netio_set_psk_hex() (see main()).
static uint8_t g_psk[32]{};
static bool g_psk_ready = false;

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool netio_set_psk_hex(const char* hex64) {
  if (!hex64 || std::strlen(hex64) != 64) return false;
  uint8_t key[32];
  for (int i = 0; i < 32; i++) {
    int hi = hex_nibble(hex64[i * 2]);
    int lo = hex_nibble(hex64[i * 2 + 1]);
    if (hi < 0 || lo < 0) return false;
    key[i] = (uint8_t)((hi << 4) | lo);
  }
  std::memcpy(g_psk, key, 32);
  OPENSSL_cleanse(key, 32);
  g_psk_ready = true;
  return true;
}

// Per-socket session key cache (derived by handshake; used by send_frame/recv_frame)
static std::unordered_map<uint64_t, std::array<uint8_t,32>> g_keys;
static std::mutex g_keys_mu;

static uint64_t sock_id(SOCKET s) { return (uint64_t)reinterpret_cast<uintptr_t>(s); }

void netio_forget_session(SOCKET s) {
  std::lock_guard<std::mutex> lk(g_keys_mu);
  g_keys.erase(sock_id(s));
}

static void set_key(SOCKET s, const uint8_t k[32]) {
  std::lock_guard<std::mutex> lk(g_keys_mu);
  std::array<uint8_t,32> tmp{};
  std::memcpy(tmp.data(), k, 32);
  g_keys[sock_id(s)] = tmp;
}

static bool get_key(SOCKET s, uint8_t out[32]) {
  std::lock_guard<std::mutex> lk(g_keys_mu);
  auto it = g_keys.find(sock_id(s));
  if (it == g_keys.end()) return false;
  std::memcpy(out, it->second.data(), 32);
  return true;
}

// ---------------- I/O ----------------
bool send_all(SOCKET s, const void* buf, int len) {
  const char* p = (const char*)buf;
  int sent = 0;
  while (sent < len) {
    int n = send(s, p + sent, len - sent, 0);
    if (n <= 0) return false;
    sent += n;
  }
  return true;
}

bool recv_all(SOCKET s, void* buf, int len) {
  char* p = (char*)buf;
  int got = 0;
  while (got < len) {
    int n = recv(s, p + got, len - got, 0);
    if (n <= 0) return false;
    got += n;
  }
  return true;
}

// ---------------- KDF / MAC ----------------
static bool hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                        const uint8_t* salt, size_t salt_len,
                        const uint8_t* info, size_t info_len,
                        uint8_t* out, size_t out_len) {
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (!pctx) return false;
  bool ok = false;

  if (EVP_PKEY_derive_init(pctx) != 1) goto done;
  if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) != 1) goto done;
  if (salt_len && EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)salt_len) != 1) goto done;
  if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int)ikm_len) != 1) goto done;
  if (info_len && EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)info_len) != 1) goto done;

  {
    size_t l = out_len;
    if (EVP_PKEY_derive(pctx, out, &l) != 1) goto done;
    if (l != out_len) goto done;
  }
  ok = true;

done:
  EVP_PKEY_CTX_free(pctx);
  return ok;
}

static bool hmac_sha256(const uint8_t* key, size_t key_len,
                        const uint8_t* data, size_t data_len,
                        uint8_t out_mac[32]) {
  unsigned int mac_len = 0;
  unsigned char* r = HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out_mac, &mac_len);
  return r && mac_len == 32;
}

// ---------------- X25519 ----------------
static bool x25519_gen(std::array<uint8_t,32>& pub, EVP_PKEY** out_priv) {
  *out_priv = nullptr;
  EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
  if (!kctx) return false;

  EVP_PKEY* pkey = nullptr;
  bool ok = false;

  if (EVP_PKEY_keygen_init(kctx) != 1) goto done;
  if (EVP_PKEY_keygen(kctx, &pkey) != 1) goto done;

  {
    size_t n = pub.size();
    if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &n) != 1) goto done;
    if (n != pub.size()) goto done;
  }

  *out_priv = pkey; pkey = nullptr;
  ok = true;

done:
  if (pkey) EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(kctx);
  return ok;
}

static bool x25519_shared(EVP_PKEY* my_priv, const uint8_t peer_pub[32],
                          std::array<uint8_t,32>& shared) {
  EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pub, 32);
  if (!peer) return false;

  EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(my_priv, nullptr);
  if (!dctx) { EVP_PKEY_free(peer); return false; }

  bool ok = false;
  size_t outlen = shared.size();

  if (EVP_PKEY_derive_init(dctx) != 1) goto done;
  if (EVP_PKEY_derive_set_peer(dctx, peer) != 1) goto done;
  if (EVP_PKEY_derive(dctx, shared.data(), &outlen) != 1) goto done;
  if (outlen != shared.size()) goto done;

  ok = true;

done:
  EVP_PKEY_CTX_free(dctx);
  EVP_PKEY_free(peer);
  return ok;
}

// transcript = "HS1"||Cpub||Spub||Cnonce||Snonce
static void build_transcript(const uint8_t Cpub[32], const uint8_t Spub[32],
                             const uint8_t Cn[16], const uint8_t Sn[16],
                             std::vector<uint8_t>& t) {
  t.clear();
  t.push_back('H'); t.push_back('S'); t.push_back('1');
  t.insert(t.end(), Cpub, Cpub + 32);
  t.insert(t.end(), Spub, Spub + 32);
  t.insert(t.end(), Cn, Cn + 16);
  t.insert(t.end(), Sn, Sn + 16);
}

static bool derive_session_key(const std::array<uint8_t,32>& shared,
                               const uint8_t Cn[16], const uint8_t Sn[16],
                               uint8_t out_key[32]) {
  uint8_t salt[32];
  std::memcpy(salt, Cn, 16);
  std::memcpy(salt + 16, Sn, 16);
  const char* info = "chat-aesgcm-v1";
  return hkdf_sha256(shared.data(), shared.size(),
                     salt, sizeof(salt),
                     (const uint8_t*)info, std::strlen(info),
                     out_key, 32);
}

// ---------------- AES-256-GCM ----------------
// Nonces are random (96-bit) rather than a counter. Per NIST SP 800-38D, the
// collision risk for random nonces under one key becomes non-negligible
// around ~2^32 messages -- comfortably above what this chat's usage
// produces per session, but a long-lived, high-throughput connection should
// switch to a counter-based nonce instead.
static bool gcm_encrypt(const uint8_t key[32],
                        const uint8_t* pt, uint32_t pt_len,
                        uint8_t nonce[NONCE_SIZE],
                        std::vector<uint8_t>& ct,
                        uint8_t tag[TAG_SIZE]) {
  if (RAND_bytes(nonce, NONCE_SIZE) != 1) return false;

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;

  bool ok = false;
  int outlen = 0;
  ct.assign(pt_len, 0);

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) goto done;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr) != 1) goto done;
  if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) goto done;

  if (pt_len && EVP_EncryptUpdate(ctx, ct.data(), &outlen, pt, (int)pt_len) != 1) goto done;
  if (EVP_EncryptFinal_ex(ctx, nullptr, &outlen) != 1) goto done;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1) goto done;

  ok = true;

done:
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

static bool gcm_decrypt(const uint8_t key[32],
                        const uint8_t nonce[NONCE_SIZE],
                        const uint8_t* ct, uint32_t ct_len,
                        const uint8_t tag[TAG_SIZE],
                        std::vector<uint8_t>& pt) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;

  bool ok = false;
  int outlen = 0;
  pt.assign(ct_len, 0);

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) goto done;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr) != 1) goto done;
  if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) goto done;

  if (ct_len && EVP_DecryptUpdate(ctx, pt.data(), &outlen, ct, (int)ct_len) != 1) goto done;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void*)tag) != 1) goto done;
  if (EVP_DecryptFinal_ex(ctx, nullptr, &outlen) != 1) goto done;

  ok = true;

done:
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

// ---------------- Handshake (AKE) ----------------
// ClientHello: "HS1C"||Cpub(32)||Cn(16)
// ServerHello: "HS1S"||Spub(32)||Sn(16)||Smac(32)
// ClientAuth : "HS1A"||Cmac(32)
// Smac/Cmac = HMAC(PSK, transcript)
bool netio_handshake_client(SOCKET s) {
  if (!g_psk_ready) return false;

  std::array<uint8_t,32> Cpub{};
  EVP_PKEY* Cpriv = nullptr;
  if (!x25519_gen(Cpub, &Cpriv)) return false;

  uint8_t Cn[HELLO_NONCE_SIZE]{};
  if (RAND_bytes(Cn, HELLO_NONCE_SIZE) != 1) { EVP_PKEY_free(Cpriv); return false; }

  const char mC[4] = {'H','S','1','C'};
  if (!send_all(s, mC, 4) ||
      !send_all(s, Cpub.data(), 32) ||
      !send_all(s, Cn, 16)) {
    EVP_PKEY_free(Cpriv);
    return false;
  }

  char mS[4]{};
  uint8_t Spub[32]{}, Sn[16]{}, Smac[32]{};
  if (!recv_all(s, mS, 4) || std::memcmp(mS, "HS1S", 4) != 0 ||
      !recv_all(s, Spub, 32) ||
      !recv_all(s, Sn, 16) ||
      !recv_all(s, Smac, 32)) {
    EVP_PKEY_free(Cpriv);
    return false;
  }

  std::vector<uint8_t> tr;
  build_transcript(Cpub.data(), Spub, Cn, Sn, tr);

  uint8_t exp_smac[32]{};
  if (!hmac_sha256(g_psk, sizeof(g_psk), tr.data(), tr.size(), exp_smac) ||
      CRYPTO_memcmp(Smac, exp_smac, 32) != 0) {
    EVP_PKEY_free(Cpriv);
    return false;
  }

  std::array<uint8_t,32> shared{};
  if (!x25519_shared(Cpriv, Spub, shared)) { EVP_PKEY_free(Cpriv); return false; }

  uint8_t session_key[32]{};
  if (!derive_session_key(shared, Cn, Sn, session_key)) { EVP_PKEY_free(Cpriv); return false; }

  uint8_t Cmac[32]{};
  if (!hmac_sha256(g_psk, sizeof(g_psk), tr.data(), tr.size(), Cmac)) {
    EVP_PKEY_free(Cpriv);
    return false;
  }

  const char mA[4] = {'H','S','1','A'};
  if (!send_all(s, mA, 4) || !send_all(s, Cmac, 32)) {
    OPENSSL_cleanse(session_key, 32);
    EVP_PKEY_free(Cpriv);
    return false;
  }

  EVP_PKEY_free(Cpriv);
  set_key(s, session_key);
  OPENSSL_cleanse(session_key, 32);
  return true;
}

bool netio_handshake_server(SOCKET s) {
  if (!g_psk_ready) return false;

  char mC[4]{};
  uint8_t Cpub[32]{}, Cn[16]{};

  if (!recv_all(s, mC, 4) || std::memcmp(mC, "HS1C", 4) != 0 ||
      !recv_all(s, Cpub, 32) ||
      !recv_all(s, Cn, 16)) {
    return false;
  }

  std::array<uint8_t,32> Spub{};
  EVP_PKEY* Spriv = nullptr;
  if (!x25519_gen(Spub, &Spriv)) return false;

  uint8_t Sn[16]{};
  if (RAND_bytes(Sn, 16) != 1) { EVP_PKEY_free(Spriv); return false; }

  std::vector<uint8_t> tr;
  build_transcript(Cpub, Spub.data(), Cn, Sn, tr);

  uint8_t Smac[32]{};
  if (!hmac_sha256(g_psk, sizeof(g_psk), tr.data(), tr.size(), Smac)) {
    EVP_PKEY_free(Spriv);
    return false;
  }

  const char mS[4] = {'H','S','1','S'};
  if (!send_all(s, mS, 4) ||
      !send_all(s, Spub.data(), 32) ||
      !send_all(s, Sn, 16) ||
      !send_all(s, Smac, 32)) {
    EVP_PKEY_free(Spriv);
    return false;
  }

  std::array<uint8_t,32> shared{};
  if (!x25519_shared(Spriv, Cpub, shared)) { EVP_PKEY_free(Spriv); return false; }

  uint8_t session_key[32]{};
  if (!derive_session_key(shared, Cn, Sn, session_key)) { EVP_PKEY_free(Spriv); return false; }

  char mA[4]{};
  uint8_t Cmac[32]{};
  if (!recv_all(s, mA, 4) || std::memcmp(mA, "HS1A", 4) != 0 ||
      !recv_all(s, Cmac, 32)) {
    OPENSSL_cleanse(session_key, 32);
    EVP_PKEY_free(Spriv);
    return false;
  }

  uint8_t exp_cmac[32]{};
  if (!hmac_sha256(g_psk, sizeof(g_psk), tr.data(), tr.size(), exp_cmac) ||
      CRYPTO_memcmp(Cmac, exp_cmac, 32) != 0) {
    OPENSSL_cleanse(session_key, 32);
    EVP_PKEY_free(Spriv);
    return false;
  }

  EVP_PKEY_free(Spriv);
  set_key(s, session_key);
  OPENSSL_cleanse(session_key, 32);
  return true;
}

// ---------------- Frames ----------------
bool send_frame(SOCKET s, const uint8_t* plaintext, uint32_t len) {
  uint8_t key[32]{};
  if (!get_key(s, key)) {
    std::cerr << "[-] send_frame: call netio_handshake_* first\n";
    return false;
  }

  uint8_t nonce[NONCE_SIZE]{};
  uint8_t tag[TAG_SIZE]{};
  std::vector<uint8_t> ct;

  if (!gcm_encrypt(key, plaintext, len, nonce, ct, tag)) {
    OPENSSL_cleanse(key, 32);
    return false;
  }
  OPENSSL_cleanse(key, 32);

  uint32_t payload_len = (uint32_t)(NONCE_SIZE + ct.size() + TAG_SIZE);
  uint32_t be_len = htonl(payload_len);

  if (!send_all(s, &be_len, 4)) return false;
  if (!send_all(s, nonce, NONCE_SIZE)) return false;
  if (!ct.empty() && !send_all(s, ct.data(), (int)ct.size())) return false;
  if (!send_all(s, tag, TAG_SIZE)) return false;
  return true;
}

bool recv_frame(SOCKET s, std::vector<uint8_t>& out_plaintext, uint32_t max_len) {
  uint8_t key[32]{};
  if (!get_key(s, key)) {
    std::cerr << "[-] recv_frame: call netio_handshake_* first\n";
    return false;
  }

  uint32_t be_len = 0;
  if (!recv_all(s, &be_len, 4)) { OPENSSL_cleanse(key, 32); return false; }

  uint32_t payload_len = ntohl(be_len);
  if (payload_len > max_len || payload_len < (uint32_t)(NONCE_SIZE + TAG_SIZE)) {
    OPENSSL_cleanse(key, 32);
    return false;
  }

  std::vector<uint8_t> payload(payload_len);
  if (!recv_all(s, payload.data(), (int)payload.size())) {
    OPENSSL_cleanse(key, 32);
    return false;
  }

  const uint8_t* nonce = payload.data();
  const uint8_t* tag   = payload.data() + payload_len - TAG_SIZE;
  const uint8_t* ct    = payload.data() + NONCE_SIZE;
  uint32_t ct_len = payload_len - NONCE_SIZE - TAG_SIZE;

  bool ok = gcm_decrypt(key, nonce, ct, ct_len, tag, out_plaintext);
  OPENSSL_cleanse(key, 32);
  return ok;
}
