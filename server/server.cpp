// server.cpp
#include "platform.h"
#include "net_io.h"

#include <atomic>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

static std::mutex g_log_mu;
static std::atomic<uint64_t> g_sid{1};

// Soft cap on concurrent connections (best-effort DoS mitigation, not a hard
// guarantee -- a few connections arriving simultaneously can briefly exceed
// it). No per-IP limiting; this only bounds total load.
static constexpr int MAX_CONNECTIONS = 100;
static std::atomic<int> g_active_connections{0};

static void log_line(uint64_t sid, const char* ip, uint16_t port, const std::string& msg) {
  std::lock_guard<std::mutex> lk(g_log_mu);
  std::cout << "[" << sid << " " << ip << ":" << port << "] " << msg << "\n";
}

static void handle_client(SOCKET cfd, const sockaddr_in& caddr) {
  uint64_t sid = g_sid.fetch_add(1);

  char cip[INET_ADDRSTRLEN]{};
  inet_ntop(AF_INET, &caddr.sin_addr, cip, sizeof(cip));
  uint16_t cport = ntohs(caddr.sin_port);

  if (g_active_connections.fetch_add(1) >= MAX_CONNECTIONS) {
    log_line(sid, cip, cport, "rejected: server at max connections (" + std::to_string(MAX_CONNECTIONS) + ")");
    g_active_connections.fetch_sub(1);
    netio_forget_session(cfd);
    closesocket(cfd);
    return;
  }
  struct ConnGuard {
    std::atomic<int>* count;
    ~ConnGuard() { count->fetch_sub(1); }
  } conn_guard{&g_active_connections};

  log_line(sid, cip, cport, "connected");

  if (!netio_handshake_server(cfd)) {
    log_line(sid, cip, cport, "handshake failed (MITM or wrong PSK)");
    netio_forget_session(cfd);
    closesocket(cfd);
    return;
  }

  const std::string greet = "Hello from server (AES-GCM + AKE)\n";
  if (!send_frame(cfd, (const uint8_t*)greet.data(), (uint32_t)greet.size())) {
    log_line(sid, cip, cport, "failed to send greeting");
    netio_forget_session(cfd);
    closesocket(cfd);
    return;
  }

  constexpr uint32_t MAX_MSG = 64 * 1024;
  while (true) {
    std::vector<uint8_t> msg;
    if (!recv_frame(cfd, msg, MAX_MSG)) {
      log_line(sid, cip, cport, "disconnected or protocol error");
      break;
    }

    std::string text(msg.begin(), msg.end());
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) text.pop_back();

    if (text == "BYE") {
      const std::string bye = "Server: BYE\n";
      (void)send_frame(cfd, (const uint8_t*)bye.data(), (uint32_t)bye.size());
      log_line(sid, cip, cport, "BYE received (closing)");
      break;
    }

    log_line(sid, cip, cport, "msg: " + text);

    const std::string echo = "Server received: " + text + "\n";
    if (!send_frame(cfd, (const uint8_t*)echo.data(), (uint32_t)echo.size())) {
      log_line(sid, cip, cport, "failed to send echo");
      break;
    }
  }

  netio_forget_session(cfd);
  closesocket(cfd);
  log_line(sid, cip, cport, "session closed");
}

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "Usage: server <ip> <port>\n";
    return 1;
  }
  const char* ip = argv[1];

  int port = 0;
  try { port = std::stoi(argv[2]); }
  catch (...) {
    std::cerr << "Invalid port\n";
    return 1;
  }
  if (port <= 0 || port > 65535) {
    std::cerr << "Port out of range\n";
    return 1;
  }

  const char* psk_hex = std::getenv("CHAT_PSK");
  if (!psk_hex || !netio_set_psk_hex(psk_hex)) {
    std::cerr << "Error: CHAT_PSK environment variable must be set to a 64-character\n"
              << "hex string (32-byte pre-shared key), matching the client's.\n"
              << "Generate one with: openssl rand -hex 32\n";
    return 1;
  }

#ifdef _WIN32
  WSADATA wsa{};
  if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
    std::cerr << "WSAStartup failed\n";
    return 1;
  }
#endif

  SOCKET sfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sfd == INVALID_SOCKET) {
    print_sock_error("socket");
#ifdef _WIN32
    WSACleanup();
#endif
    return 1;
  }

  int opt = 1;
  if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
    print_sock_error("setsockopt(SO_REUSEADDR)");
  }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
    std::cerr << "Invalid IP\n";
    closesocket(sfd);
#ifdef _WIN32
    WSACleanup();
#endif
    return 1;
  }

  if (bind(sfd, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
    print_sock_error("bind");
    closesocket(sfd);
#ifdef _WIN32
    WSACleanup();
#endif
    return 1;
  }

  if (listen(sfd, 16) == SOCKET_ERROR) {
    print_sock_error("listen");
    closesocket(sfd);
#ifdef _WIN32
    WSACleanup();
#endif
    return 1;
  }

  {
    std::lock_guard<std::mutex> lk(g_log_mu);
    std::cout << "[*] Listening on " << ip << ":" << port << "\n";
  }

  while (true) {
    sockaddr_in caddr{};
    socklen_t clen = sizeof(caddr);
    SOCKET cfd = accept(sfd, (sockaddr*)&caddr, &clen);
    if (cfd == INVALID_SOCKET) {
      print_sock_error("accept");
      continue;
    }

    std::thread([cfd, caddr]() mutable {
      handle_client(cfd, caddr);
    }).detach();
  }

  // Unreachable
  closesocket(sfd);
#ifdef _WIN32
  WSACleanup();
#endif
  return 0;
}
