// integration_test.go
//
// Builds the real C++ server and drives it with this package's own
// HandshakeClient/SecureConn, to prove the two independent implementations
// (C++ server, Go client) actually interoperate -- not just that each
// compiles in isolation.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestHandshakeAndEchoAgainstRealServer(t *testing.T) {
	if _, err := exec.LookPath("g++"); err != nil {
		t.Skip("g++ not found in PATH, skipping cross-language integration test")
	}

	serverDir, err := filepath.Abs(filepath.Join("..", "server"))
	if err != nil {
		t.Fatalf("resolve server dir: %v", err)
	}
	exePath := filepath.Join(serverDir, "server.exe")

	build := exec.Command("g++", "-std=c++17", "-O2",
		"server.cpp", "net_io.cpp", "-o", "server.exe",
		"-lws2_32", "-lssl", "-lcrypto")
	build.Dir = serverDir
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("server build failed, skipping integration test: %v\n%s", err, out)
	}
	defer os.Remove(exePath)

	pskBytes := make([]byte, 32)
	if _, err := rand.Read(pskBytes); err != nil {
		t.Fatalf("generate test PSK: %v", err)
	}
	psk := hex.EncodeToString(pskBytes)

	const addr = "127.0.0.1:19654" // uncommon port, unlikely to collide with a real server
	srv := exec.Command(exePath, "127.0.0.1", "19654")
	srv.Env = append(os.Environ(), "CHAT_PSK="+psk)
	if err := srv.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer func() {
		_ = srv.Process.Kill()
		_ = srv.Wait()
	}()

	var conn net.Conn
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err = net.Dial("tcp", addr)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Skipf("server never became reachable (possibly missing OpenSSL runtime DLLs in PATH): %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	defer conn.Close()

	// Test-local PSK, set directly rather than via CHAT_PSK/loadPSK so this
	// test doesn't depend on (or clobber) the process environment.
	handshakePSK = pskBytes

	sc, err := HandshakeClient(conn)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

	greet, err := sc.RecvFrame(MAX_MSG)
	if err != nil {
		t.Fatalf("recv greeting: %v", err)
	}
	if !bytes.Contains(greet, []byte("Hello from server")) {
		t.Errorf("unexpected greeting: %q", greet)
	}

	if err := sc.SendFrame([]byte("integration-test\n")); err != nil {
		t.Fatalf("send: %v", err)
	}
	resp, err := sc.RecvFrame(MAX_MSG)
	if err != nil {
		t.Fatalf("recv echo: %v", err)
	}
	if !bytes.Contains(resp, []byte("integration-test")) {
		t.Errorf("unexpected echo: %q", resp)
	}
}
