#pragma once

#include <cstdint>
#include <cstring>
#include <iostream>

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  using socklen_t = int;
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <unistd.h>
  #include <errno.h>
  #define SOCKET int
  #define INVALID_SOCKET (-1)
  #define SOCKET_ERROR (-1)
  static inline int closesocket(int s) { return close(s); }
#endif

inline void print_sock_error(const char* where) {
#ifdef _WIN32
  int e = WSAGetLastError();
  std::cerr << "[-] " << where << " failed (WSA error " << e << ")\n";
#else
  std::cerr << "[-] " << where << " failed: " << std::strerror(errno) << "\n";
#endif
}
