// client.go
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

const MAX_MSG = 64 * 1024

type Session struct {
	ip   string
	port string
	conn net.Conn
	sc   *SecureConn
}

func (s *Session) Active() bool { return s != nil && s.conn != nil && s.sc != nil }

func printHelp() {
	fmt.Println("Commands:")
	fmt.Println("  /help                  Show this help")
	fmt.Println("  /connect <ip> <port>   Start a session (connect + handshake)")
	fmt.Println("  /reconnect             Reconnect using last ip/port")
	fmt.Println("  /close                 Gracefully close current session (BYE)")
	fmt.Println("  /quit                  Close and exit")
	fmt.Println("  <text>                 Send message (requires active session)")
}

func gracefulClose(sess *Session) {
	if sess == nil || sess.conn == nil {
		return
	}
	// Best-effort BYE
	_ = sess.sc.SendFrame([]byte("BYE\n"))
	_, _ = sess.sc.RecvFrame(MAX_MSG)
	_ = sess.conn.Close()
	sess.conn = nil
	sess.sc = nil
}

func hardClose(sess *Session) {
	if sess == nil || sess.conn == nil {
		return
	}
	_ = sess.conn.Close()
	sess.conn = nil
	sess.sc = nil
}

func connectTo(ip, port string) (*Session, error) {
	addr := ip + ":" + port
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	sc, err := HandshakeClient(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}

	greet, err := sc.RecvFrame(MAX_MSG)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read greeting: %w", err)
	}
	fmt.Print("Server says: ", string(greet))

	return &Session{ip: ip, port: port, conn: conn, sc: sc}, nil
}

func main() {
	if err := loadPSK(); err != nil {
		fmt.Println("Error:", err)
		fmt.Println(`Set it with (PowerShell): $env:CHAT_PSK = "<64 hex chars>"`)
		os.Exit(1)
	}

	fmt.Println("Secure Client (AES-GCM + AKE)")
	printHelp()

	reader := bufio.NewReader(os.Stdin)
	var sess *Session

	for {
		fmt.Print("> ")
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("\nInput error. Exiting.")
			gracefulClose(sess)
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Commands
		if strings.HasPrefix(line, "/") {
			parts := strings.Fields(line)
			cmd := parts[0]

			switch cmd {
			case "/help":
				printHelp()

			case "/connect":
				if len(parts) != 3 {
					fmt.Println("Usage: /connect <ip> <port>")
					continue
				}
				// Close any existing session
				if sess != nil && sess.Active() {
					fmt.Println("[*] Closing current session...")
					gracefulClose(sess)
				}
				fmt.Println("[*] Connecting...")
				newSess, err := connectTo(parts[1], parts[2])
				if err != nil {
					fmt.Println("Connect failed:", err)
					sess = &Session{ip: parts[1], port: parts[2]}
					continue
				}
				sess = newSess
				fmt.Println("[+] Session started.")

			case "/reconnect":
				if sess == nil || sess.ip == "" || sess.port == "" {
					fmt.Println("No previous address. Use /connect <ip> <port> first.")
					continue
				}
				if sess.Active() {
					fmt.Println("[*] Closing current session...")
					gracefulClose(sess)
				}
				fmt.Println("[*] Reconnecting to", sess.ip+":"+sess.port, "...")
				newSess, err := connectTo(sess.ip, sess.port)
				if err != nil {
					fmt.Println("Reconnect failed:", err)
					// keep last ip/port for next try
					hardClose(sess)
					continue
				}
				sess = newSess
				fmt.Println("[+] Session started.")

			case "/close":
				if sess == nil || !sess.Active() {
					fmt.Println("No active session.")
					continue
				}
				fmt.Println("[*] Closing session (BYE)...")
				gracefulClose(sess)
				fmt.Println("[+] Session closed. Use /reconnect or /connect.")

			case "/quit", "/exit":
				fmt.Println("[*] Exiting...")
				gracefulClose(sess)
				return

			default:
				fmt.Println("Unknown command. Use /help")
			}
			continue
		}

		// Normal message
		if sess == nil || !sess.Active() {
			fmt.Println("No active session. Use /connect <ip> <port> or /reconnect.")
			continue
		}

		if err := sess.sc.SendFrame([]byte(line + "\n")); err != nil {
			fmt.Println("Connection lost (send failed). Use /reconnect.")
			hardClose(sess)
			continue
		}

		resp, err := sess.sc.RecvFrame(MAX_MSG)
		if err != nil {
			fmt.Println("Connection lost (recv failed). Use /reconnect.")
			hardClose(sess)
			continue
		}
		fmt.Print(string(resp))
	}
}
