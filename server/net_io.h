// net_io.h
#pragma once
#include "platform.h"
#include <vector>
#include <cstdint>

bool send_all(SOCKET s, const void* buf, int len);
bool recv_all(SOCKET s, void* buf, int len);

// Call once at startup, BEFORE any handshake, with a 64-char hex string
// (32-byte key). Returns false if hex64 is null, wrong length, or not valid hex.
bool netio_set_psk_hex(const char* hex64);

// Call once per connection BEFORE send_frame/recv_frame.
bool netio_handshake_client(SOCKET s);
bool netio_handshake_server(SOCKET s);

// Optional cleanup (recommended).
void netio_forget_session(SOCKET s);

// Encrypted frame:
// wire = [u32_be payload_len][ payload = nonce(12) || ciphertext || tag(16) ]
bool send_frame(SOCKET s, const uint8_t* plaintext, uint32_t len);
bool recv_frame(SOCKET s, std::vector<uint8_t>& out_plaintext, uint32_t max_len);
