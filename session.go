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
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	sessionFile          = "sessions.json"
	sessionInactivityMax = 10 * time.Minute
	sessionAbsoluteMax   = 12 * time.Hour
)

// A Grant is one thing a command needs to read: usually a single op:// ref.
// Touch ID approves grants, not accounts or vaults: approving one says nothing
// about any other.
type Grant struct {
	Key string // identifies exactly what is read; this is what an approval covers
	Ref string // how the Touch ID prompt shows it, as op://group/rest
}

// An Approval records that Touch ID was given for one grant in one terminal
// session. It lapses after sessionInactivityMax without the grant being used,
// and sessionAbsoluteMax after it was given.
type Approval struct {
	Created    time.Time `json:"created"`
	LastAccess time.Time `json:"last_access"`
	MAC        string    `json:"mac"` // see approvalMAC
}

// SessionStore is the contents of sessions.json. Any process running as the
// user can write that file, so an approval only counts if its MAC checks out.
type SessionStore struct {
	Approvals map[string]*Approval `json:"approvals"` // keyed by approvalID
}

// testDataDir can be set by test builds to override the data directory.
var testDataDir string

func getDataDir() (string, error) {
	var dir string
	if testDataDir != "" {
		dir = testDataDir
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".opcli")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

func getSessionPath() (string, error) {
	dir, err := getDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, sessionFile), nil
}

// testSessionKey can be set by test builds to override session key detection.
var testSessionKey string

// findAncestorTTY walks up the process tree to find an ancestor with a TTY.
// This handles cases like hyperfine where the current process has no TTY
// but an ancestor (the shell) does.
func findAncestorTTY() string {
	pid := os.Getppid()
	for pid > 1 {
		// Use ps to get the TTY for this process
		out, err := exec.Command("ps", "-o", "tty=,ppid=", "-p", fmt.Sprintf("%d", pid)).Output()
		if err != nil {
			break
		}
		fields := strings.Fields(string(bytes.TrimSpace(out)))
		if len(fields) < 2 {
			break
		}
		tty := fields[0]
		if tty != "??" && tty != "" {
			// Found a TTY - convert to device path
			if strings.HasPrefix(tty, "ttys") {
				return "/dev/" + tty
			}
			return "/dev/tty" + tty
		}
		// Move to parent
		var ppid int
		if _, err := fmt.Sscanf(fields[1], "%d", &ppid); err != nil || ppid <= 1 {
			break
		}
		pid = ppid
	}
	return ""
}

// currentTTYPath returns the TTY device path (e.g. "/dev/ttys003") attached
// to one of our standard file descriptors, or "" if none is available.
func currentTTYPath() string {
	if cTTY := C.getTTYName(); cTTY != nil {
		return C.GoString(cTTY)
	}
	return ""
}

// getSessionKey returns a unique key for the current terminal session.
// Based on TTY device + TTY start time, ensuring uniqueness even after TTY reuse.
func getSessionKey() (string, error) {
	if testSessionKey != "" {
		return testSessionKey, nil
	}

	// Get the actual TTY device path (e.g., /dev/ttys001)
	var ttyPath string
	if cTTY := C.getTTYName(); cTTY != nil {
		ttyPath = C.GoString(cTTY)
	} else if ancestorTTY := findAncestorTTY(); ancestorTTY != "" {
		// Walk up process tree to find an ancestor with a TTY
		// (handles running inside hyperfine, etc.)
		ttyPath = ancestorTTY
	} else {
		return "", fmt.Errorf("no controlling terminal")
	}

	return sessionKeyForTTY(ttyPath)
}

// sessionKeyForTTY returns the session key of the terminal session currently
// on the TTY device at ttyPath.
func sessionKeyForTTY(ttyPath string) (string, error) {
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
			return &SessionStore{Approvals: make(map[string]*Approval)}, nil
		}
		return nil, err
	}

	var store SessionStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("failed to parse session store: %w", err)
	}

	if store.Approvals == nil {
		store.Approvals = make(map[string]*Approval)
	}

	return &store, nil
}

// updateSessions applies update to the session store on disk. It holds a
// lock meanwhile: opcli processes often run side by side, and one working
// from a stale copy of the store would drop the others' approvals.
func updateSessions(update func(*SessionStore)) error {
	path, err := getSessionPath()
	if err != nil {
		return err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close() // which unlocks
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}

	store, err := loadSessions()
	if err != nil {
		return err
	}
	update(store)

	now := time.Now()
	for id, a := range store.Approvals {
		if now.Sub(a.LastAccess) > sessionInactivityMax ||
			now.Sub(a.Created) > sessionAbsoluteMax {
			delete(store.Approvals, id)
		}
	}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	// Atomic write, so that readers (who don't take the lock) never see half a file.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// approvalID is the key of the approval of grantKey in the terminal session
// sessionKey. It is a MAC rather than the two strings themselves so that
// sessions.json doesn't list the names of everything you've read lately.
func approvalID(secret []byte, sessionKey, grantKey string) string {
	h := hmac.New(sha256.New, secret)
	fmt.Fprintf(h, "id:%d:%s%s", len(sessionKey), sessionKey, grantKey)
	return hex.EncodeToString(h.Sum(nil))
}

// approvalMAC authenticates an approval. It covers both timestamps: an
// unauthenticated LastAccess would let anyone who can write sessions.json keep
// an approval alive for the full 12 hours.
func approvalMAC(secret []byte, id string, a *Approval) string {
	h := hmac.New(sha256.New, secret)
	fmt.Fprintf(h, "mac:%s:%d:%d", id, a.Created.UnixNano(), a.LastAccess.UnixNano())
	return hex.EncodeToString(h.Sum(nil))
}

// Authorize makes sure every grant is approved for the current terminal
// session, asking for Touch ID for the ones that aren't. The prompt lists
// exactly the grants it is approving.
func Authorize(grants []Grant) error {
	if len(grants) == 0 {
		return nil
	}

	// Without a terminal there is nothing to scope an approval to: ask every time.
	sessionKey, sessionKeyErr := getSessionKey()
	if sessionKeyErr != nil {
		var refs []string
		for _, g := range grants {
			refs = append(refs, g.Ref)
		}
		if err := AuthenticateBiometric(refs); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Warning: Touch ID will be needed again next time: %v\n", sessionKeyErr)
		return nil
	}

	secret, err := GetSessionSecret()
	if err != nil {
		return err
	}
	store, err := loadSessions()
	if err != nil {
		return err
	}

	// Entries of the store as it should be once this is done: the approvals
	// in use, freshened, and those that Touch ID is about to give.
	now := time.Now()
	approvals := map[string]*Approval{}
	var unapproved []Grant
	for _, g := range grants {
		id := approvalID(secret, sessionKey, g.Key)
		a, ok := store.Approvals[id]
		if ok && hmac.Equal([]byte(a.MAC), []byte(approvalMAC(secret, id, a))) &&
			now.Sub(a.LastAccess) <= sessionInactivityMax && now.Sub(a.Created) <= sessionAbsoluteMax {
			a.LastAccess = now
			approvals[id] = a
		} else {
			unapproved = append(unapproved, g)
		}
	}

	if len(unapproved) > 0 {
		var refs []string
		for _, g := range unapproved {
			refs = append(refs, g.Ref)
		}
		if err := AuthenticateBiometric(refs); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
		now := time.Now() // the prompt may have been up for a while
		for _, g := range unapproved {
			approvals[approvalID(secret, sessionKey, g.Key)] = &Approval{Created: now, LastAccess: now}
		}
	}

	return updateSessions(func(store *SessionStore) {
		for id, a := range approvals {
			a.MAC = approvalMAC(secret, id, a)
			store.Approvals[id] = a
		}
	})
}
