package main

/*
#include <stdlib.h>
#include <sys/stat.h>
*/
import "C"
import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
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

// An Approval records that Touch ID was given for one grant in one scope. It
// lapses after sessionInactivityMax without the grant being used,
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

// A scope is who an approval is given to: one run of a coding agent, or one
// terminal tab. It is named by a process among our ancestors (the "anchor"),
// which is something a process can't lie about: it can't choose its ancestors.
// (opcli used to go by which terminal its stdin was, and any process can open
// any of your terminals.)
//
// This keeps one agent or tab from using what was approved for another. It
// is no defense against malware running as you, which can get itself run by
// the anchor: say, by editing a file that the agent or your shell executes.
type scope struct {
	key     string    // identifies the anchor: its pid and start time
	agent   string    // which of agentNames the anchor is, or "" for a terminal tab
	pid     int       // of the anchor
	tdev    int32     // the anchor's controlling terminal, or -1
	started time.Time // when the anchor started
}

// agentNames are the coding agents that get a scope of their own, by the name
// they run under. A process that merely calls itself one of these gains
// nothing: it becomes the anchor of a new scope, with no approvals in it.
var agentNames = []string{"claude", "codex"}

// testSessionKey can be set by test builds to override the scope's key.
var testSessionKey string

// currentScope finds the scope this process is in: the nearest ancestor that
// is a coding agent, or else the terminal tab, which is to say the outermost
// ancestor that has a controlling terminal. That is the tab's first process
// (login, or the shell), whose own parent is the terminal emulator or its
// server; those have no terminal, and are never the anchor, since every tab
// descends from them.
func currentScope() (*scope, error) {
	if testSessionKey != "" {
		return &scope{key: testSessionKey, tdev: -1}, nil
	}

	var tab *scope
	for pid := os.Getppid(); pid > 1; {
		kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
		if err != nil {
			return nil, fmt.Errorf("looking up ancestor process %d: %w", pid, err)
		}
		start := kp.Proc.P_starttime
		p := &scope{
			key:     fmt.Sprintf("%d-%d-%06d", pid, start.Sec, start.Usec),
			pid:     pid,
			tdev:    kp.Eproc.Tdev,
			started: time.Unix(start.Sec, int64(start.Usec)*1000),
		}

		// The name it runs under is argv[0]: Claude Code's executable is
		// named for its version. The arguments of other users' processes
		// (login runs as root) can't be read; those keep the kernel's name.
		name := unix.ByteSliceToString(kp.Proc.P_comm[:])
		if args, err := unix.SysctlRaw("kern.procargs2", pid); err == nil && len(args) > 4 {
			// argc, the executable's path, padding, then argv, all NUL-terminated.
			_, rest, _ := bytes.Cut(args[4:], []byte{0})
			argv0, _, _ := bytes.Cut(bytes.TrimLeft(rest, "\x00"), []byte{0})
			name = strings.TrimPrefix(filepath.Base(string(argv0)), "-")
		}
		if slices.Contains(agentNames, name) {
			p.agent = name
			return p, nil
		}

		if p.tdev != -1 {
			tab = p
		}
		pid = int(kp.Eproc.Ppid)
	}
	if tab == nil {
		return nil, errors.New("not running under a terminal or a coding agent")
	}
	return tab, nil
}

// scopeKeyLive reports whether the anchor that a scope key names is still running.
func scopeKeyLive(key string) bool {
	var pid int
	var sec, usec int64
	if n, _ := fmt.Sscanf(key, "%d-%d-%d", &pid, &sec, &usec); n != 3 {
		return false
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	return err == nil && kp.Proc.P_starttime.Sec == sec && int64(kp.Proc.P_starttime.Usec) == usec
}

// describe says what the scope is, for the Touch ID prompt: a title for it,
// and how to refer to it in a sentence.
func (s *scope) describe() (title, noun string) {
	switch s.agent {
	case "claude":
		title = claudeSessionTitle(s.pid)
		if title == "" {
			title = "Claude Code session"
		}
		return title, "this Claude Code session"
	case "codex":
		return "Codex session", "this Codex session"
	}
	if s.tdev == -1 {
		return "Terminal tab", "this terminal tab"
	}
	return "Terminal tab " + C.GoString(C.devname(C.dev_t(s.tdev), C.S_IFCHR)), "this terminal tab"
}

// claudeSessionTitle returns the title of the conversation in the Claude Code
// process pid, as Claude Code shows it, or "" if it can't be found. This
// reads Claude Code's own files, whose layout is nobody's promise: a running
// process's ~/.claude/sessions/<pid>.json names its session, and the session's
// transcript records each title it is given.
func claudeSessionTitle(pid int) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(home, ".claude", "sessions", fmt.Sprintf("%d.json", pid)))
	if err != nil {
		return ""
	}
	var session struct {
		SessionID string `json:"sessionId"`
		Name      string `json:"name"`
	}
	if json.Unmarshal(data, &session) != nil || !regexp.MustCompile(`^[0-9a-f-]+$`).MatchString(session.SessionID) {
		return ""
	}

	// The last title wins, and one the user chose beats one Claude made up.
	var aiTitle, customTitle string
	transcripts, _ := filepath.Glob(filepath.Join(home, ".claude", "projects", "*", session.SessionID+".jsonl"))
	for _, path := range transcripts {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		lines := bufio.NewReader(f)
		for {
			line, err := lines.ReadBytes('\n')
			if bytes.Contains(line, []byte(`-title"`)) {
				var record struct {
					Type        string `json:"type"`
					AITitle     string `json:"aiTitle"`
					CustomTitle string `json:"customTitle"`
				}
				if json.Unmarshal(line, &record) == nil {
					switch record.Type {
					case "ai-title":
						aiTitle = record.AITitle
					case "custom-title":
						customTitle = record.CustomTitle
					}
				}
			}
			if err != nil {
				break
			}
		}
		f.Close()
	}
	if customTitle != "" {
		return customTitle
	}
	if aiTitle != "" {
		return aiTitle
	}
	return session.Name
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

// approvalID is the key of the approval of grantKey in the scope with key
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

// Authorize makes sure every grant is approved for the current scope, asking
// for Touch ID for the ones that aren't. The prompt lists
// exactly the grants it is approving.
func Authorize(grants []Grant) error {
	if len(grants) == 0 {
		return nil
	}

	// Without a scope there is nobody to give an approval to: ask every time.
	sc, scopeErr := currentScope()
	if scopeErr != nil {
		var refs []string
		for _, g := range grants {
			refs = append(refs, g.Ref)
		}
		if err := AuthenticateBiometric(refs, nil); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Warning: Touch ID will be needed again next time: %v\n", scopeErr)
		return nil
	}
	sessionKey := sc.key

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
		if err := AuthenticateBiometric(refs, sc); err != nil {
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
