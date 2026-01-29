package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/awnumar/memguard"
	"golang.org/x/term"
)

const (
	socketName = "opcli.sock"
	tokenName  = "opcli.token"
)

func getDaemonDir() (string, error) {
	if d := os.Getenv("OPCLI_TEST_DATA_DIR"); d != "" {
		if err := os.MkdirAll(d, 0700); err != nil {
			return "", err
		}
		return d, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".opcli")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

func getSocketPath() (string, error) {
	dir, err := getDaemonDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, socketName), nil
}

func getTokenPath() (string, error) {
	dir, err := getDaemonDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, tokenName), nil
}

type daemonRequest struct {
	Token string `json:"token"`
}

type daemonResponse struct {
	Password  string `json:"password,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
	Error     string `json:"error,omitempty"`
}

func cmdDaemon() error {
	// Initialize memguard
	memguard.CatchInterrupt()
	defer memguard.Purge()

	socketPath, err := getSocketPath()
	if err != nil {
		return fmt.Errorf("failed to get socket path: %w", err)
	}

	tokenPath, err := getTokenPath()
	if err != nil {
		return fmt.Errorf("failed to get token path: %w", err)
	}

	// Remove existing socket
	os.Remove(socketPath)

	// Generate random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	// Write token to file (readable only by owner)
	if err := os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
		return fmt.Errorf("failed to write token: %w", err)
	}
	defer os.Remove(tokenPath)

	// Get secret key
	fmt.Fprint(os.Stderr, "Enter Secret Key (A3-XXXXX-...): ")
	var secretKey string
	fmt.Scanln(&secretKey)

	// Get master password
	fmt.Fprint(os.Stderr, "Enter Master Password: ")
	pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Fprintln(os.Stderr)

	// Store in memguard enclave
	passwordEnclave := memguard.NewEnclave(pwBytes)
	secretKeyEnclave := memguard.NewEnclave([]byte(secretKey))

	// Clear the original
	for i := range pwBytes {
		pwBytes[i] = 0
	}

	// Listen on Unix socket
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket: %w", err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)

	// Set socket permissions
	if err := os.Chmod(socketPath, 0600); err != nil {
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Daemon started. Press Ctrl+C to stop.")

	// Handle shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "\nShutting down...")
		listener.Close()
	}()

	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			// Check if we're shutting down
			select {
			case <-sigChan:
				return nil
			default:
				fmt.Fprintf(os.Stderr, "Accept error: %v\n", err)
				continue
			}
		}

		go handleConnection(conn, token, passwordEnclave, secretKeyEnclave)
	}
}

func handleConnection(conn net.Conn, token string, passwordEnclave, secretKeyEnclave *memguard.Enclave) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	var req daemonRequest
	if err := decoder.Decode(&req); err != nil {
		sendResponse(conn, daemonResponse{Error: "invalid request"})
		return
	}

	if req.Token != token {
		sendResponse(conn, daemonResponse{Error: "invalid token"})
		return
	}

	// Open enclaves to get the values
	pwBuf, err := passwordEnclave.Open()
	if err != nil {
		sendResponse(conn, daemonResponse{Error: "failed to access password"})
		return
	}
	defer pwBuf.Destroy()

	skBuf, err := secretKeyEnclave.Open()
	if err != nil {
		sendResponse(conn, daemonResponse{Error: "failed to access secret key"})
		return
	}
	defer skBuf.Destroy()

	sendResponse(conn, daemonResponse{
		Password:  string(pwBuf.Bytes()),
		SecretKey: string(skBuf.Bytes()),
	})
}

func sendResponse(conn net.Conn, resp daemonResponse) {
	encoder := json.NewEncoder(conn)
	encoder.Encode(resp)
}

// getCredentialsFromDaemon tries to get credentials from the daemon
// Returns password, secretKey, ok
func getCredentialsFromDaemon() (string, string, bool) {
	socketPath, err := getSocketPath()
	if err != nil {
		return "", "", false
	}

	tokenPath, err := getTokenPath()
	if err != nil {
		return "", "", false
	}

	// Read token
	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", "", false
	}
	token := string(tokenBytes)

	// Connect to daemon
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return "", "", false
	}
	defer conn.Close()

	// Send request
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(daemonRequest{Token: token}); err != nil {
		return "", "", false
	}

	// Read response
	decoder := json.NewDecoder(conn)
	var resp daemonResponse
	if err := decoder.Decode(&resp); err != nil {
		return "", "", false
	}

	if resp.Error != "" {
		return "", "", false
	}

	return resp.Password, resp.SecretKey, true
}
