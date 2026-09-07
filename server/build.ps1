# Builds server.exe. Requires MinGW g++ and OpenSSL dev libs (see Readme.md).
$ErrorActionPreference = "Stop"
g++ -std=c++17 -O2 -Wall -Wextra server.cpp net_io.cpp -o server.exe -lws2_32 -lssl -lcrypto
Write-Host "Built server.exe"
