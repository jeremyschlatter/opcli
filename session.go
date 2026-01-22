package main

/*
#include <unistd.h>
#include <stdlib.h>

// Try to get tty name from any of the standard file descriptors
char* getTTYName() {
    char* name = ttyname(0);  // stdin
    if (name) return name;
    name = ttyname(1);  // stdout
    if (name) return name;
    name = ttyname(2);  // stderr
    return name;
}
*/
import "C"
import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const (
	sessionFile          = "sessions.json"
	sessionInactivityMax = 10 * time.Minute
	sessionAbsoluteMax   = 12 * time.Hour
)

type Session struct {
	AccountID  string    `json:"account_id"`
	Created    time.Time `json:"created"`
	LastAccess time.Time `json:"last_access"`
	MAC        string    `json:"mac"` // HMAC of session data, verified using Keychain secret
}

type SessionStore struct {
	Sessions map[string]*Session `json:"sessions"`
}

func getSessionPath() (string, error) {
	dir, err := getDaemonDir() // reuse from daemon.go
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, sessionFile), nil
}

// getSessionKey returns a unique key for the current terminal session.
// Based on TTY device + TTY start time, ensuring uniqueness even after TTY reuse.
func getSessionKey() (string, error) {
	// Get the actual TTY device path (e.g., /dev/ttys001)
	cTTY := C.getTTYName()
	if cTTY == nil {
		return "", fmt.Errorf("no controlling terminal")
	}
	ttyPath := C.GoString(cTTY)

	// Get the TTY's creation/start time
	var stat syscall.Stat_t
	if err := syscall.Stat(ttyPath, &stat); err != nil {
		return "", fmt.Errorf("cannot stat TTY %s: %w", ttyPath, err)
	}

	// Use the TTY path + birthtime to create a unique session key
	// Birthtime is when the PTY was created, stays constant for its lifetime
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s:%d", ttyPath, stat.Birthtimespec.Sec)))
	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

func loadSessions() (*SessionStore, error) {
	path, err := getSessionPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &SessionStore{Sessions: make(map[string]*Session)}, nil
		}
		return nil, err
	}

	var store SessionStore
	if err := json.Unmarshal(data, &store); err != nil {
		// Corrupted file, start fresh
		return &SessionStore{Sessions: make(map[string]*Session)}, nil
	}

	if store.Sessions == nil {
		store.Sessions = make(map[string]*Session)
	}

	return &store, nil
}

func saveSessions(store *SessionStore) error {
	path, err := getSessionPath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// computeSessionMAC computes HMAC for session data using the Keychain secret.
func computeSessionMAC(secret []byte, sessionKey, accountID string, created time.Time) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(fmt.Sprintf("%s:%s:%d", sessionKey, accountID, created.Unix())))
	return hex.EncodeToString(h.Sum(nil))
}

// GetValidSession returns a valid session for the current TTY, or nil if none exists.
func GetValidSession(accountID string) (*Session, error) {
	sessionKey, err := getSessionKey()
	if err != nil {
		return nil, err
	}

	store, err := loadSessions()
	if err != nil {
		return nil, err
	}

	session, ok := store.Sessions[sessionKey]
	if !ok {
		return nil, nil
	}

	// Check if session matches the account
	if session.AccountID != accountID {
		return nil, nil
	}

	// Verify MAC using Keychain secret (only opcli can read this)
	secret, err := GetSessionSecret(accountID)
	if err != nil {
		return nil, err
	}
	expectedMAC := computeSessionMAC(secret, sessionKey, session.AccountID, session.Created)
	if session.MAC != expectedMAC {
		// Invalid MAC - session was forged or corrupted
		delete(store.Sessions, sessionKey)
		saveSessions(store)
		return nil, nil
	}

	now := time.Now()

	// Check inactivity timeout (10 minutes)
	if now.Sub(session.LastAccess) > sessionInactivityMax {
		delete(store.Sessions, sessionKey)
		saveSessions(store)
		return nil, nil
	}

	// Check absolute timeout (12 hours)
	if now.Sub(session.Created) > sessionAbsoluteMax {
		delete(store.Sessions, sessionKey)
		saveSessions(store)
		return nil, nil
	}

	// Update last access time and recompute MAC
	session.LastAccess = now
	if err := saveSessions(store); err != nil {
		// Non-fatal, session still valid
	}

	return session, nil
}

// CreateSession creates a new session for the current TTY.
func CreateSession(accountID string) (*Session, error) {
	sessionKey, err := getSessionKey()
	if err != nil {
		return nil, err
	}

	store, err := loadSessions()
	if err != nil {
		return nil, err
	}

	// Get or create session secret from Keychain
	secret, err := GetSessionSecret(accountID)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	session := &Session{
		AccountID:  accountID,
		Created:    now,
		LastAccess: now,
	}
	session.MAC = computeSessionMAC(secret, sessionKey, accountID, now)

	store.Sessions[sessionKey] = session

	if err := saveSessions(store); err != nil {
		return nil, err
	}

	return session, nil
}


// CleanExpiredSessions removes all expired sessions from the store.
func CleanExpiredSessions() error {
	store, err := loadSessions()
	if err != nil {
		return err
	}

	now := time.Now()
	changed := false

	for key, session := range store.Sessions {
		if now.Sub(session.LastAccess) > sessionInactivityMax ||
			now.Sub(session.Created) > sessionAbsoluteMax {
			delete(store.Sessions, key)
			changed = true
		}
	}

	if changed {
		return saveSessions(store)
	}
	return nil
}
