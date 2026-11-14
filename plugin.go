package main

// Shell plugins: `opcli plugin ...`, modeled on `op plugin ...`.
//
// The plugins themselves are upstream's (github.com/1Password/shell-plugins),
// compiled in via plugin_registry.go. This file is the host side: choosing a
// 1Password item for a plugin's credential, remembering the choice, and
// provisioning the credential to the plugin's executable when it runs.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/1Password/shell-plugins/sdk"
	"github.com/1Password/shell-plugins/sdk/schema"
	"github.com/AlecAivazis/survey/v2"
	"golang.org/x/term"
)

// pluginConfig says which 1Password item holds a plugin's credential. It is
// modeled on op's format (~/.op/plugins/<executable>.json), with two
// differences: the `fields` extension, and there is one config per plugin
// (<plugin>.json), shared by all of its executables (eg fly and flyctl),
// where op has one per executable.
type pluginConfig struct {
	AccountID   string             `json:"account_id"`
	Credentials []pluginCredential `json:"credentials"`
}

type pluginCredential struct {
	Plugin         string `json:"plugin"`
	CredentialType string `json:"credential_type"`
	UsageID        string `json:"usage_id"`
	VaultID        string `json:"vault_id"`
	ItemID         string `json:"item_id"`

	// opcli extension. Plugins expect item fields to have particular labels
	// (eg "Token"). When an item's labels differ, op renames them; opcli is
	// read-only, so it records which field to use instead: credential field
	// name -> ID of the item's field.
	Fields map[string]string `json:"fields,omitempty"`
}

const (
	pluginScopeSession   = "session"
	pluginScopeDirectory = "directory"
	pluginScopeGlobal    = "global"
)

func cmdPlugin(args []string, accountFlag string) (int, error) {
	usage := func() (int, error) {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  opcli plugin list                            - List available shell plugins")
		fmt.Fprintln(os.Stderr, "  opcli plugin init [<executable>]             - Choose the 1Password item that authenticates a CLI, and shim it")
		fmt.Fprintln(os.Stderr, "  opcli plugin inspect <executable>            - Show a plugin's configuration")
		fmt.Fprintln(os.Stderr, "  opcli plugin clear <executable> [--all] [--force]")
		fmt.Fprintln(os.Stderr, "                                               - Remove a plugin's configuration")
		fmt.Fprintln(os.Stderr, "  opcli plugin run -- <executable> [<args>...] - Run a CLI with its credentials from 1Password")
		return 1, nil
	}
	if len(args) == 0 {
		return usage()
	}

	dataDir, err := getDataDir()
	if err != nil {
		return 0, err
	}
	// Shims are symlinks to opcli named for the executables that plugins
	// authenticate. Run through one, opcli is `opcli plugin run -- <name>`
	// (see main). The directory goes ahead of the real executables on the PATH.
	shimsDir := filepath.Join(dataDir, "shims")
	selfPath, err := os.Executable()
	if err != nil {
		return 0, err
	}
	self, err := os.Stat(selfPath)
	if err != nil {
		return 0, err
	}
	// shimActive reports whether running `name` runs opcli.
	shimActive := func(name string) bool {
		path, err := exec.LookPath(name)
		if err != nil {
			return false
		}
		info, err := os.Stat(path)
		return err == nil && os.SameFile(info, self)
	}

	// findExecutable looks up the plugin that handles the executable `name`.
	findExecutable := func(name string) (schema.Plugin, schema.Executable, error) {
		for _, p := range shellPlugins() {
			for _, exe := range p.Executables {
				if len(exe.Runs) != 1 || exe.Runs[0] != name {
					continue
				}
				if len(exe.Uses) != 1 || exe.Uses[0].Name == "" {
					return p, exe, fmt.Errorf("the %s plugin takes a choice of credentials from other plugins, which opcli doesn't support yet", name)
				}
				return p, exe, nil
			}
		}
		return schema.Plugin{}, schema.Executable{}, fmt.Errorf("no shell plugin for %q (see `opcli plugin list`)", name)
	}

	switch args[0] {
	case "list":
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
		fmt.Fprintln(w, "EXECUTABLE\tNAME\tREQUIRED FIELDS")
		for _, p := range shellPlugins() {
			for _, exe := range p.Executables {
				if _, _, err := findExecutable(exe.Runs[0]); err != nil {
					continue
				}
				credType, _ := pluginCredentialType(p, exe.Uses[0])
				var required []string
				for _, f := range credType.Fields {
					if !f.Optional {
						required = append(required, f.Name.String())
					}
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", exe.Runs[0], p.Platform.Name, strings.Join(required, ", "))
			}
		}
		return 0, w.Flush()

	case "init":
		var name string
		switch len(args) {
		case 1:
			var options, names []string
			for _, p := range shellPlugins() {
				for _, exe := range p.Executables {
					if _, _, err := findExecutable(exe.Runs[0]); err == nil {
						options = append(options, fmt.Sprintf("%s (%s)", exe.Runs[0], p.Platform.Name))
						names = append(names, exe.Runs[0])
					}
				}
			}
			var i int
			if err := survey.AskOne(&survey.Select{Message: "Choose which CLI you want to authenticate with 1Password:", Options: options}, &i); err != nil {
				return 0, err
			}
			name = names[i]
		case 2:
			name = args[1]
		default:
			return usage()
		}
		p, exe, err := findExecutable(name)
		if err != nil {
			return 0, err
		}
		if _, err := pluginConfigure(p, exe, accountFlag); err != nil {
			return 0, err
		}

		// Shim every executable that authenticates with this credential,
		// if it's installed: a shim for a missing executable would make it
		// look installed.
		credType, _ := pluginCredentialType(p, exe.Uses[0])
		if err := os.MkdirAll(shimsDir, 0700); err != nil {
			return 0, err
		}
		var shimmed []string
		for _, sibling := range p.Executables {
			siblingName := sibling.Runs[0]
			if _, _, err := findExecutable(siblingName); err != nil {
				continue
			}
			if siblingCredType, _ := pluginCredentialType(p, sibling.Uses[0]); siblingCredType.pluginName != credType.pluginName {
				continue
			}
			if _, err := pluginLookPath(siblingName); err != nil && siblingName != name {
				continue
			}
			shim := filepath.Join(shimsDir, siblingName)
			if err := os.Remove(shim); err != nil && !os.IsNotExist(err) {
				return 0, err
			}
			if err := os.Symlink(selfPath, shim); err != nil {
				return 0, err
			}
			shimmed = append(shimmed, siblingName)
		}

		fmt.Printf("\nInstalled shims in %s: %s\n\n", tildePath(shimsDir), strings.Join(shimmed, ", "))
		if shimActive(name) {
			fmt.Printf("Run any %s command to see it in action!\n", name)
			return 0, nil
		}
		fmt.Printf("The last step is to put the shims ahead of %s on your PATH.\nYou can do so by running the following command:\n\n", name)
		switch filepath.Base(os.Getenv("SHELL")) {
		case "fish":
			fmt.Printf("  fish_add_path --prepend %s\n\n", shimsDir)
		case "zsh":
			fmt.Printf("  echo 'export PATH=\"%s:$PATH\"' >> ~/.zshrc && source ~/.zshrc\n\n", shimsDir)
		case "bash":
			fmt.Printf("  echo 'export PATH=\"%s:$PATH\"' >> ~/.bashrc && source ~/.bashrc\n\n", shimsDir)
		default:
			fmt.Printf("  export PATH=\"%s:$PATH\"   # in your shell's startup file\n\n", shimsDir)
		}
		fmt.Printf("Afterwards, run any %s command to see it in action!\n", name)
		return 0, nil

	case "inspect":
		if len(args) != 2 {
			return usage()
		}
		name := args[1]
		p, exe, err := findExecutable(name)
		if err != nil {
			return 0, err
		}
		credType, _ := pluginCredentialType(p, exe.Uses[0])
		fmt.Printf("%s\n\nShim\n\n", p.Platform.Name)
		if shimActive(name) {
			fmt.Printf("✔ %s runs through opcli\n", name)
		} else if _, err := os.Lstat(filepath.Join(shimsDir, name)); err != nil {
			fmt.Printf("✘ No shim for %s. Run `opcli plugin init %s` to install one.\n", name, name)
		} else {
			fmt.Printf("✘ The shim for %s isn't being used. Put %s ahead of it on your PATH.\n", name, tildePath(shimsDir))
		}

		fmt.Printf("\nConfigured Credentials\n\n")
		configs, err := pluginConfigs(credType.pluginName)
		if err != nil {
			return 0, err
		}
		if len(configs) == 0 {
			fmt.Printf("No settings currently configured. Run `opcli plugin init %s` to configure a credential.\n", name)
			return 0, nil
		}
		for i, c := range configs {
			aks, err := openKeychains(c.AccountID, nil)
			if err != nil {
				return 0, err
			}
			defer aks.Close()
			aks.pendingRefs = []string{"op://shell plugin/" + name}
			ak, err := aks.get("", nil)
			if err != nil {
				return 0, err
			}
			cred := c.Credentials[0]
			item, err := getItem(ak.db, ak.accountUUID, cred.VaultID, cred.ItemID)
			if err != nil {
				return 0, err
			}
			overview, err := ak.decryptOverview(cred.VaultID, &item.EncOverview)
			if err != nil {
				return 0, err
			}
			vault, err := getVaultByUUID(ak.db, ak.accountUUID, cred.VaultID)
			if err != nil {
				return 0, err
			}
			vaultName, _, err := ak.decryptVaultName(vault)
			if err != nil {
				return 0, err
			}
			scope := map[string]string{
				pluginScopeSession:   "This terminal session",
				pluginScopeDirectory: "Directory " + tildePath(filepath.Dir(filepath.Dir(filepath.Dir(c.path)))),
				pluginScopeGlobal:    "Global default",
			}[c.scope]
			inUse := ""
			if i == 0 && len(configs) > 1 {
				inUse = "  ← in use here"
			}
			fmt.Printf("%s: %s (%s)%s\n", scope, overview.Title, vaultName, inUse)
		}
		return 0, nil

	case "clear":
		var name string
		var all, force bool
		for _, arg := range args[1:] {
			switch {
			case arg == "--all":
				all = true
			case arg == "--force" || arg == "-f":
				force = true
			case strings.HasPrefix(arg, "-") || name != "":
				return usage()
			default:
				name = arg
			}
		}
		if name == "" {
			return usage()
		}
		p, exe, err := findExecutable(name)
		if err != nil {
			return 0, err
		}
		credType, _ := pluginCredentialType(p, exe.Uses[0])
		configs, err := pluginConfigs(credType.pluginName)
		if err != nil {
			return 0, err
		}
		if len(configs) == 0 {
			fmt.Printf("No configuration for %s to clear.\n", p.Platform.Name)
			return 0, nil
		}
		if !all {
			configs = configs[:1]
		}
		for _, c := range configs {
			if !force {
				ok := false
				if err := survey.AskOne(&survey.Confirm{Message: fmt.Sprintf("Clear the %s configuration for %s (%s)?", c.scope, p.Platform.Name, tildePath(c.path))}, &ok); err != nil {
					return 0, err
				}
				if !ok {
					continue
				}
			}
			if err := os.Remove(c.path); err != nil {
				return 0, err
			}
			fmt.Printf("Cleared the %s configuration for %s.\n", c.scope, p.Platform.Name)
		}
		return 0, nil

	case "run":
		cmdArgs := args[1:]
		if len(cmdArgs) > 0 && cmdArgs[0] == "--" {
			cmdArgs = cmdArgs[1:]
		}
		if len(cmdArgs) == 0 {
			return usage()
		}
		name := cmdArgs[0]
		p, exe, err := findExecutable(name)
		if err != nil {
			return 0, err
		}
		use := exe.Uses[0]
		credType, provisioner := pluginCredentialType(p, use)

		// Commands like `gh --version` don't need credentials: skip 1Password entirely.
		needsAuth := sdk.NeedsAuthenticationInput{CredentialType: credType.Name.ID().String(), CommandArgs: cmdArgs[1:]}
		if exe.NeedsAuth != nil && !exe.NeedsAuth(needsAuth) || use.NeedsAuth != nil && !use.NeedsAuth(needsAuth) {
			binary, err := pluginLookPath(name)
			if err != nil {
				return 0, err
			}
			return 0, syscall.Exec(binary, cmdArgs, os.Environ())
		}

		var config *pluginConfig
		configs, err := pluginConfigs(credType.pluginName)
		if err != nil {
			return 0, err
		}
		if len(configs) > 0 {
			config = &configs[0].pluginConfig
		} else if term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) {
			if config, err = pluginConfigure(p, exe, accountFlag); err != nil {
				return 0, err
			}
			fmt.Println()
		} else {
			return 0, fmt.Errorf("no credential configured for %s (run `opcli plugin init %s`)", name, name)
		}
		cred := config.Credentials[0]
		if cred.Plugin != credType.pluginName || cred.CredentialType != credType.Name.ID().String() {
			return 0, fmt.Errorf("the configuration for %s is for a %s/%s credential, but the plugin now uses %s/%s (run `opcli plugin init %s`)",
				name, cred.Plugin, cred.CredentialType, credType.pluginName, credType.Name.ID(), name)
		}

		// Read the credential from 1Password.
		itemFields := map[sdk.FieldName]string{}
		{
			aks, err := openKeychains(config.AccountID, nil)
			if err != nil {
				return 0, err
			}
			aks.pendingRefs = []string{"op://shell plugin/" + name}
			ak, err := aks.get("", nil)
			if err != nil {
				aks.Close()
				return 0, err
			}
			item, err := getItem(ak.db, ak.accountUUID, cred.VaultID, cred.ItemID)
			if err != nil {
				aks.Close()
				return 0, err
			}
			details, err := ak.decryptDetail(cred.VaultID, &item.EncDetails)
			aks.Close()
			if err != nil {
				return 0, err
			}
			fields := pluginItemFields(details)
			for _, cf := range credType.Fields {
				i := -1
				if id, ok := cred.Fields[cf.Name.String()]; ok {
					for j, f := range fields {
						if f.id == id {
							i = j
							break
						}
					}
					if i == -1 {
						return 0, fmt.Errorf("the item configured for %s no longer has the field chosen as its %s (run `opcli plugin init %s`)", name, cf.Name, name)
					}
				} else if i = pluginFieldByLabel(fields, cf); i == -1 {
					if cf.Optional {
						continue
					}
					return 0, fmt.Errorf("the item configured for %s has no %q field (run `opcli plugin init %s`)", name, cf.Name, name)
				}
				itemFields[cf.Name] = fields[i].value
			}
		}

		home, err := os.UserHomeDir()
		if err != nil {
			return 0, err
		}
		tempDir, err := os.MkdirTemp("", "opcli-plugin-")
		if err != nil {
			return 0, err
		}
		defer os.RemoveAll(tempDir)

		// The provision cache (data a provisioner saves for its next run, eg
		// AWS session tokens) is not persisted: provisioners always start cold.
		out := sdk.ProvisionOutput{
			Environment: map[string]string{},
			CommandLine: cmdArgs,
			Files:       map[string]sdk.OutputFile{},
			Cache:       sdk.CacheOperations{Puts: map[string]sdk.CacheEntry{}},
		}
		provisioner.Provision(context.Background(), sdk.ProvisionInput{HomeDir: home, TempDir: tempDir, Cache: sdk.CacheState{}, ItemFields: itemFields}, &out)
		if errs := out.Diagnostics.Errors; len(errs) > 0 {
			return 0, fmt.Errorf("provisioning the %s for %s: %s", credType.Name, name, errs[0].Message)
		}
		for path, file := range out.Files {
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				return 0, err
			}
			if err := os.WriteFile(path, file.Contents, 0600); err != nil {
				return 0, err
			}
			defer os.Remove(path)
		}

		// Run as a child (not exec) so we can clean up afterwards. The child
		// gets the terminal directly: no output masking, so TUIs work.
		binary, err := pluginLookPath(out.CommandLine[0])
		if err != nil {
			return 0, err
		}
		cmd := exec.Command(binary)
		cmd.Args = out.CommandLine
		cmd.Env = os.Environ()
		for k, v := range out.Environment {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		// ^C and ^\ go from the terminal to the whole foreground process
		// group, child included: we just need to outlive it. (Caught rather
		// than ignored, because a child inherits ignored signals.) Signals
		// aimed at us alone get forwarded.
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
		if err := cmd.Start(); err != nil {
			return 0, err
		}
		go func() {
			for sig := range sigCh {
				if sig == syscall.SIGTERM || sig == syscall.SIGHUP {
					cmd.Process.Signal(sig)
				}
			}
		}()
		waitErr := cmd.Wait()

		var deprovisioned sdk.DeprovisionOutput
		provisioner.Deprovision(context.Background(), sdk.DeprovisionInput{HomeDir: home, TempDir: tempDir}, &deprovisioned)
		for _, e := range deprovisioned.Diagnostics.Errors {
			fmt.Fprintf(os.Stderr, "opcli: cleaning up the %s for %s: %s\n", credType.Name, name, e.Message)
		}

		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			if status := exitErr.Sys().(syscall.WaitStatus); status.Signaled() {
				return 128 + int(status.Signal()), nil
			}
			return exitErr.ExitCode(), nil
		}
		return 0, waitErr

	default:
		return usage()
	}
}

// pluginLookPath finds an executable on the PATH like exec.LookPath, but skips
// opcli itself: when a shim (a symlink to opcli, named for the executable) comes
// first on the PATH, we want the real executable behind it.
func pluginLookPath(name string) (string, error) {
	if strings.Contains(name, "/") {
		return exec.LookPath(name)
	}
	selfPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	self, err := os.Stat(selfPath)
	if err != nil {
		return "", err
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() && info.Mode()&0111 != 0 && !os.SameFile(info, self) {
			return path, nil
		}
	}
	return "", fmt.Errorf("%s: executable not found in $PATH", name)
}

// pluginCredentialType resolves the credential an executable uses, along with
// the provisioner that hands it to the executable.
func pluginCredentialType(p schema.Plugin, usage schema.CredentialUsage) (struct {
	schema.CredentialType
	pluginName string
}, sdk.Provisioner) {
	pluginName := p.Name
	if usage.Plugin != "" {
		pluginName = usage.Plugin
	}
	for _, candidate := range append([]schema.Plugin{p}, shellPlugins()...) {
		if candidate.Name != pluginName {
			continue
		}
		for _, credType := range candidate.Credentials {
			if credType.Name == usage.Name {
				provisioner := usage.Provisioner
				if provisioner == nil {
					provisioner = credType.DefaultProvisioner
				}
				return struct {
					schema.CredentialType
					pluginName string
				}{credType, pluginName}, provisioner
			}
		}
	}
	panic(fmt.Sprintf("plugin %s uses credential %s/%s, which doesn't exist", p.Name, pluginName, usage.Name))
}

type foundPluginConfig struct {
	pluginConfig
	scope string
	path  string
}

// pluginConfigPath returns where the config for the plugin `name` lives in
// the given scope. For the directory scope that's under the current directory.
func pluginConfigPath(name, scope string) (string, error) {
	dataDir, err := getDataDir()
	if err != nil {
		return "", err
	}
	switch scope {
	case pluginScopeSession:
		key, err := getSessionKey()
		if err != nil {
			return "", err
		}
		return filepath.Join(dataDir, "plugins", "sessions", key, name+".json"), nil
	case pluginScopeDirectory:
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return filepath.Join(cwd, ".opcli", "plugins", name+".json"), nil
	case pluginScopeGlobal:
		return filepath.Join(dataDir, "plugins", name+".json"), nil
	}
	panic("unknown plugin scope: " + scope)
}

// pluginConfigs returns the configs that apply to the plugin `name` here
// and now, highest precedence first: this terminal session, the enclosing
// directories from the current one outward, then the global default.
func pluginConfigs(name string) ([]foundPluginConfig, error) {
	var found []foundPluginConfig
	add := func(scope, path string) error {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			return nil
		} else if err != nil {
			return err
		}
		c := foundPluginConfig{scope: scope, path: path}
		if err := json.Unmarshal(data, &c.pluginConfig); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if len(c.Credentials) != 1 {
			return fmt.Errorf("%s: expected exactly one credential, found %d", path, len(c.Credentials))
		}
		found = append(found, c)
		return nil
	}

	globalPath, err := pluginConfigPath(name, pluginScopeGlobal)
	if err != nil {
		return nil, err
	}

	// A session config lasts as long as its terminal. No terminal, no session scope.
	if _, err := getSessionKey(); err == nil {
		path, err := pluginConfigPath(name, pluginScopeSession)
		if err != nil {
			return nil, err
		}
		if err := add(pluginScopeSession, path); err != nil {
			return nil, err
		}
	}

	dir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	for {
		path := filepath.Join(dir, ".opcli", "plugins", name+".json")
		// (In the home directory, the directory config *is* the global one.)
		if path != globalPath {
			if err := add(pluginScopeDirectory, path); err != nil {
				return nil, err
			}
		}
		if dir == filepath.Dir(dir) {
			break
		}
		dir = filepath.Dir(dir)
	}

	if err := add(pluginScopeGlobal, globalPath); err != nil {
		return nil, err
	}
	return found, nil
}

type pluginItemField struct {
	id, label, section, value string
}

// pluginItemFields flattens an item into the fields a credential can come from.
func pluginItemFields(item *DecryptedItem) []pluginItemField {
	var fields []pluginItemField
	for i := range item.Fields {
		f := &item.Fields[i]
		fields = append(fields, pluginItemField{f.FieldID(), f.FieldLabel(), "", f.FieldValue()})
	}
	for i := range item.Sections {
		s := &item.Sections[i]
		section := s.Title
		if section == "" {
			section = s.Name
		}
		for j := range s.Fields {
			f := &s.Fields[j]
			fields = append(fields, pluginItemField{f.FieldID(), f.FieldLabel(), section, f.FieldValue()})
		}
	}
	// Password items without a username keep the password as a top-level key (see findField).
	if len(item.Fields) == 0 {
		for _, k := range sortedKeys(item.Extras) {
			fields = append(fields, pluginItemField{k, k, "", item.Extras[k]})
		}
	}
	return fields
}

// pluginFieldByLabel finds the field labeled the way the plugin expects for
// the credential field cf: by its name, or else one of its alternative names.
// Returns -1 if there is none.
func pluginFieldByLabel(fields []pluginItemField, cf schema.CredentialField) int {
	for _, label := range append([]string{cf.Name.String()}, cf.AlternativeNames...) {
		for i, f := range fields {
			if f.label == label {
				return i
			}
		}
	}
	return -1
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// tildePath abbreviates the home directory in a path, for display.
func tildePath(path string) string {
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(path, home+"/") {
		return "~" + path[len(home):]
	}
	return path
}

// pluginConfigure interactively picks the 1Password item that authenticates
// exe (and the plugin's other executables) and when to use it, and saves the choice.
func pluginConfigure(p schema.Plugin, exe schema.Executable, accountFlag string) (*pluginConfig, error) {
	credType, _ := pluginCredentialType(p, exe.Uses[0])
	fmt.Printf("\n%s\nAuthenticate with %s.\n\n", p.Platform.Name, credType.Name)

	// Credentials the plugin's importer finds already on this machine (in
	// config files, environment variables...). op offers to import these into
	// 1Password. opcli is read-only, so it uses them to point out which
	// 1Password items hold the credential this CLI is already using.
	type detected struct {
		fields map[sdk.FieldName]string
		source string
	}
	var detecteds []detected
	if credType.Importer != nil {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		var imported sdk.ImportOutput
		credType.Importer(context.Background(), sdk.ImportInput{HomeDir: home, RootDir: "/", OS: runtime.GOOS}, &imported)
		for _, attempt := range imported.Attempts {
			var sources []string
			for _, v := range attempt.Source.Env {
				sources = append(sources, "$"+v)
			}
			for _, f := range attempt.Source.Files {
				sources = append(sources, tildePath(f))
			}
			sources = append(sources, attempt.Source.Other.Value...)
			source := strings.Join(sources, ", ")
			for _, e := range attempt.Diagnostics.Errors {
				fmt.Fprintf(os.Stderr, "Warning: couldn't check %s for an existing %s: %s\n", source, credType.Name, e.Message)
			}
			for _, c := range attempt.Candidates {
				fields := map[sdk.FieldName]string{}
				for k, v := range c.Fields {
					if v != "" {
						fields[k] = v
					}
				}
				if len(fields) > 0 {
					detecteds = append(detecteds, detected{fields, source})
				}
			}
		}
	}

	// List every item, with the ones that hold a detected credential first.
	type choice struct {
		label   string
		matches bool
		account string
		cred    pluginCredential
		fields  []pluginItemField
	}
	var choices []choice
	{
		aks, err := openKeychains(accountFlag, nil)
		if err != nil {
			return nil, err
		}
		defer aks.Close()
		// Shown beside the Touch ID prompt: unlike other commands, this one reads everything.
		aks.pendingRefs = []string{"op://Full database access/every vault/every item"}

		accounts := []string{aks.defaultAccount}
		if accountFlag == "" && os.Getenv("OP_ACCOUNT") == "" && os.Getenv("OPCLI_AUTO_ACCOUNT") != "" {
			for _, uuid := range sortedKeys(aks.store.Accounts) {
				if uuid != aks.defaultAccount {
					accounts = append(accounts, uuid)
				}
			}
		}
		for _, account := range accounts {
			ak, err := aks.get(account, nil)
			if err != nil {
				return nil, err
			}
			vaults, err := getVaults(ak.db, ak.accountUUID)
			if err != nil {
				return nil, err
			}
			for _, v := range vaults {
				if v.VaultType == "S" { // system vaults, hidden like in `opcli list`
					continue
				}
				vaultName, _, err := ak.decryptVaultName(&v)
				if err != nil {
					return nil, fmt.Errorf("vault %s: %w", v.VaultUUID, err)
				}
				if len(accounts) > 1 {
					vaultName = aks.store.Accounts[account].Shorthand + ":" + vaultName
				}
				items, err := getItems(ak.db, ak.accountUUID, v.VaultUUID)
				if err != nil {
					return nil, err
				}
				for i := range items {
					overview, err := ak.decryptOverview(v.VaultUUID, &items[i].EncOverview)
					if err != nil {
						return nil, fmt.Errorf("item %s: %w", items[i].UUID, err)
					}
					details, err := ak.decryptDetail(v.VaultUUID, &items[i].EncDetails)
					if err != nil {
						return nil, fmt.Errorf("item %s: %w", items[i].UUID, err)
					}
					label := fmt.Sprintf("%s (%s)", overview.Title, vaultName)
					if overview.Ainfo != "" {
						label += " - " + overview.Ainfo
					}
					c := choice{
						label:   label,
						account: account,
						fields:  pluginItemFields(details),
						cred: pluginCredential{
							Plugin:         credType.pluginName,
							CredentialType: credType.Name.ID().String(),
							UsageID:        exe.Uses[0].ID(),
							VaultID:        v.VaultUUID,
							ItemID:         items[i].UUID,
						},
					}
				detection:
					for _, d := range detecteds {
						// The item matches if it has every detected value. Note
						// which field holds each one, unless its label already says so.
						mapping := map[string]string{}
						for _, cf := range credType.Fields {
							value, ok := d.fields[cf.Name]
							if !ok {
								continue
							}
							if j := pluginFieldByLabel(c.fields, cf); j != -1 && c.fields[j].value == value {
								continue
							}
							j := 0
							for j < len(c.fields) && c.fields[j].value != value {
								j++
							}
							if j == len(c.fields) {
								continue detection
							}
							mapping[cf.Name.String()] = c.fields[j].id
						}
						c.matches = true
						c.label += " — matches " + d.source
						if len(mapping) > 0 {
							c.cred.Fields = mapping
						}
						break
					}
					choices = append(choices, c)
				}
			}
		}
	}
	sort.SliceStable(choices, func(i, j int) bool {
		if choices[i].matches != choices[j].matches {
			return choices[i].matches
		}
		return strings.ToLower(choices[i].label) < strings.ToLower(choices[j].label)
	})
	if len(detecteds) > 0 && !choices[0].matches {
		fmt.Printf("Found your %s in %s, but no 1Password item holds it.\nTo use that one, save it in 1Password and run this again.\n\n", credType.Name, detecteds[0].source)
	}

	var chosen choice
	{
		labels := make([]string, len(choices))
		for i, c := range choices {
			labels[i] = c.label
		}
		var i int
		if err := survey.AskOne(&survey.Select{Message: fmt.Sprintf("Locate your %s:", credType.Name), Options: labels, PageSize: 10}, &i); err != nil {
			return nil, err
		}
		chosen = choices[i]
	}

	// Find each field of the credential in the item, asking when its label doesn't tell.
	for _, cf := range credType.Fields {
		if _, ok := chosen.cred.Fields[cf.Name.String()]; ok || pluginFieldByLabel(chosen.fields, cf) != -1 || cf.Optional {
			continue
		}
		var labels []string
		var ids []string
		for _, f := range chosen.fields {
			if f.value == "" {
				continue
			}
			label := f.label
			if f.section != "" {
				label += " (" + f.section + ")"
			}
			labels = append(labels, label)
			ids = append(ids, f.id)
		}
		if len(labels) == 0 {
			return nil, fmt.Errorf("that item has no fields with values")
		}
		var i int
		if err := survey.AskOne(&survey.Select{
			Message: fmt.Sprintf("This item has no field named %q. Which field holds the %s?", cf.Name, cf.Name),
			Options: labels,
			Help:    cf.MarkdownDescription,
		}, &i); err != nil {
			return nil, err
		}
		if chosen.cred.Fields == nil {
			chosen.cred.Fields = map[string]string{}
		}
		chosen.cred.Fields[cf.Name.String()] = ids[i]
	}

	scopes := []string{pluginScopeSession, pluginScopeDirectory, pluginScopeGlobal}
	var scope int
	if err := survey.AskOne(&survey.Select{
		Message: "Configure when the chosen credential(s) will be used to authenticate:",
		Options: []string{
			"Prompt me for each new terminal session",
			"Use automatically when in this directory or subdirectories",
			"Use as global default on my system",
		},
	}, &scope); err != nil {
		return nil, err
	}

	config := &pluginConfig{AccountID: chosen.account, Credentials: []pluginCredential{chosen.cred}}
	path, err := pluginConfigPath(credType.pluginName, scopes[scope])
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(config, "", "\t")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, err
	}
	if scopes[scope] == pluginScopeSession {
		// Sweep up the configs of terminal sessions that have ended.
		live := map[string]bool{filepath.Base(filepath.Dir(path)): true}
		ttys, err := filepath.Glob("/dev/ttys*")
		if err != nil {
			return nil, err
		}
		for _, tty := range ttys {
			key, err := sessionKeyForTTY(tty)
			if err != nil {
				return nil, err
			}
			live[key] = true
		}
		sessions, err := os.ReadDir(filepath.Dir(filepath.Dir(path)))
		if err != nil {
			return nil, err
		}
		for _, session := range sessions {
			if !live[session.Name()] {
				if err := os.RemoveAll(filepath.Join(filepath.Dir(filepath.Dir(path)), session.Name())); err != nil {
					return nil, err
				}
			}
		}
	}
	return config, nil
}
