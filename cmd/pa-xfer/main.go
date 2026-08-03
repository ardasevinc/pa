package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ardasevinc/pa/internal/agecmd"
	"github.com/ardasevinc/pa/internal/remote"
	"github.com/ardasevinc/pa/internal/store"
	"github.com/ardasevinc/pa/internal/transfer"
)

const usageText = `usage:
  pa-xfer export --to RECIPIENTS [options] OUTPUT
  pa-xfer import [options] BUNDLE
  pa-xfer verify [options] BUNDLE
  pa-xfer recipient [options]
  pa-xfer peer --host HOST [options]
  pa-xfer sync --host HOST --peer-fingerprint SHA256 [options]

commands:
  export      decrypt this store and create a bundle for another identity
  import      add missing bundle entries, preserving every existing name
  verify      authenticate and decode a bundle without importing it
  recipient   print this store's public recipient and fingerprint
  peer        fetch a remote store's public recipient over SSH
  sync        push then pull through a pinned, encrypted SSH transfer

common options:
  --store DIR  pa data directory (default: $PA_DIR or the pa default)
  --age PATH   age or rage executable (default: auto-detect)
  --json       emit machine-readable results
`

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 || arguments[0] == "help" || arguments[0] == "--help" || arguments[0] == "-h" {
		_, _ = io.WriteString(stdout, usageText)
		return 0
	}

	var err error
	switch arguments[0] {
	case "export":
		err = runExport(ctx, arguments[1:], stdout, stderr)
	case "import":
		err = runImport(ctx, arguments[1:], stdout, stderr)
	case "verify":
		err = runVerify(ctx, arguments[1:], stdout, stderr)
	case "recipient":
		err = runRecipient(arguments[1:], stdout, stderr)
	case "peer":
		err = runPeer(ctx, arguments[1:], stdout, stderr)
	case "sync":
		err = runSync(ctx, arguments[1:], stdout, stderr)
	case "serve":
		err = runServe(ctx, arguments[1:], stdinReader{}, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "pa-xfer: unknown command %q\n", arguments[0])
		_, _ = io.WriteString(stderr, usageText)
		return 2
	}
	if err == nil {
		return 0
	}

	var applied *transfer.AppliedError
	if errors.As(err, &applied) {
		fmt.Fprintf(stderr, "pa-xfer: %v\n", err)
		return 3
	}
	var remoteApplied *remote.RemoteAppliedError
	if errors.As(err, &remoteApplied) {
		fmt.Fprintf(stderr, "pa-xfer: %v\n", err)
		return 3
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	fmt.Fprintf(stderr, "pa-xfer: %v\n", err)
	return 1
}

// stdinReader keeps the process stdin dependency at the remote-only boundary.
type stdinReader struct{}

func (stdinReader) Read(data []byte) (int, error) { return os.Stdin.Read(data) }

type commonFlags struct {
	store string
	age   string
	json  bool
}

func addCommonFlags(flags *flag.FlagSet, values *commonFlags, stderr io.Writer) {
	flags.SetOutput(stderr)
	flags.StringVar(&values.store, "store", defaultStoreDir(), "pa data directory")
	flags.StringVar(&values.age, "age", os.Getenv("PA_AGE"), "age or rage executable")
	flags.BoolVar(&values.json, "json", false, "emit JSON")
}

func runExport(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("export", flag.ContinueOnError)
	var common commonFlags
	var recipients string
	addCommonFlags(flags, &common, stderr)
	flags.StringVar(&recipients, "to", "", "destination recipients file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if recipients == "" || flags.NArg() != 1 {
		return errors.New("usage: pa-xfer export --to RECIPIENTS [options] OUTPUT")
	}

	age, source, err := openRuntime(common)
	if err != nil {
		return err
	}
	defer source.Close()
	result, err := transfer.Export(ctx, age, source, recipients, flags.Arg(0))
	if err != nil {
		return err
	}
	if common.json {
		return writeJSON(stdout, result)
	}
	fmt.Fprintf(stdout, "exported %d entries (%d bytes) to %s\n", result.Entries, result.Bytes, result.Output)
	return nil
}

func runImport(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("import", flag.ContinueOnError)
	var common commonFlags
	addCommonFlags(flags, &common, stderr)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: pa-xfer import [options] BUNDLE")
	}

	age, destination, err := openRuntime(common)
	if err != nil {
		return err
	}
	defer destination.Close()
	result, importErr := transfer.Import(ctx, age, destination, flags.Arg(0))
	if common.json {
		if err := writeJSON(stdout, result); err != nil {
			return errors.Join(importErr, err)
		}
	} else if result.TransactionID != "" {
		fmt.Fprintf(stdout, "imported %d, skipped %d (transaction %s)\n", result.Imported, result.Skipped, result.TransactionID)
		if result.Receipt != "" {
			fmt.Fprintf(stdout, "receipt: %s\n", result.Receipt)
		}
	}
	return importErr
}

func runVerify(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	var common commonFlags
	addCommonFlags(flags, &common, stderr)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: pa-xfer verify [options] BUNDLE")
	}
	age, err := agecmd.Find(common.age)
	if err != nil {
		return err
	}
	result, err := transfer.Verify(ctx, age, filepath.Join(common.store, "identities"), flags.Arg(0))
	if err != nil {
		return err
	}
	if common.json {
		return writeJSON(stdout, result)
	}
	fmt.Fprintf(stdout, "verified %d entries (%d bytes)\n", result.Entries, result.Bytes)
	return nil
}

func runRecipient(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("recipient", flag.ContinueOnError)
	var common commonFlags
	addCommonFlags(flags, &common, stderr)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: pa-xfer recipient [options]")
	}
	directory, err := filepath.Abs(common.store)
	if err != nil {
		return fmt.Errorf("resolve store directory: %w", err)
	}
	opened, err := store.Open(directory)
	if err != nil {
		return err
	}
	recipientsPath := opened.RecipientsPath
	if err := opened.Close(); err != nil {
		return err
	}
	data, err := os.ReadFile(recipientsPath)
	if err != nil {
		return fmt.Errorf("read recipients: %w", err)
	}
	digest := sha256.Sum256(data)
	fingerprint := "sha256:" + hex.EncodeToString(digest[:])
	if common.json {
		return writeJSON(stdout, struct {
			Fingerprint string `json:"fingerprint"`
			Recipients  string `json:"recipients"`
		}{Fingerprint: fingerprint, Recipients: string(data)})
	}
	if _, err := stdout.Write(data); err != nil {
		return err
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		_, _ = io.WriteString(stdout, "\n")
	}
	fmt.Fprintf(stdout, "fingerprint %s\n", fingerprint)
	return nil
}

type sshFlags struct {
	host    string
	sshPath string
	options stringList
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, " ") }

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func addSSHFlags(flags *flag.FlagSet, values *sshFlags) {
	flags.StringVar(&values.host, "host", "", "SSH destination")
	flags.StringVar(&values.sshPath, "ssh", "", "ssh executable")
	flags.Var(&values.options, "ssh-option", "one ssh argument; repeat as needed")
}

func (s sshFlags) client() remote.Client {
	return remote.Client{Host: s.host, SSHPath: s.sshPath, SSHOptions: s.options}
}

func runPeer(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("peer", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var ssh sshFlags
	var jsonOutput bool
	addSSHFlags(flags, &ssh)
	flags.BoolVar(&jsonOutput, "json", false, "emit JSON")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if ssh.host == "" || flags.NArg() != 0 {
		return errors.New("usage: pa-xfer peer --host HOST [options]")
	}
	peer, err := ssh.client().Recipient(ctx)
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(stdout, struct {
			Fingerprint string `json:"fingerprint"`
			Recipients  string `json:"recipients"`
		}{Fingerprint: peer.Fingerprint, Recipients: string(peer.Recipients)})
	}
	if _, err := stdout.Write(peer.Recipients); err != nil {
		return err
	}
	if len(peer.Recipients) > 0 && peer.Recipients[len(peer.Recipients)-1] != '\n' {
		_, _ = io.WriteString(stdout, "\n")
	}
	fmt.Fprintf(stdout, "fingerprint %s\n", peer.Fingerprint)
	return nil
}

type syncResult struct {
	PeerFingerprint string                `json:"peer_fingerprint"`
	Pushed          transfer.ImportResult `json:"pushed"`
	Pulled          transfer.ImportResult `json:"pulled"`
}

func runSync(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("sync", flag.ContinueOnError)
	var common commonFlags
	var ssh sshFlags
	var pinnedFingerprint string
	addCommonFlags(flags, &common, stderr)
	addSSHFlags(flags, &ssh)
	flags.StringVar(&pinnedFingerprint, "peer-fingerprint", "", "expected remote recipient fingerprint")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if ssh.host == "" || pinnedFingerprint == "" || flags.NArg() != 0 {
		return errors.New("usage: pa-xfer sync --host HOST --peer-fingerprint SHA256 [options]")
	}

	age, local, err := openRuntime(common)
	if err != nil {
		return err
	}
	defer local.Close()
	if _, err := local.RequireCleanGit(); err != nil {
		return fmt.Errorf("local preflight: %w", err)
	}
	client := ssh.client()
	peer, err := client.Recipient(ctx)
	if err != nil {
		return err
	}
	if !strings.EqualFold(peer.Fingerprint, pinnedFingerprint) {
		return fmt.Errorf("remote recipient fingerprint mismatch: got %s", peer.Fingerprint)
	}

	temporaryDirectory, err := os.MkdirTemp("", "pa-sync-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporaryDirectory)
	peerRecipients := filepath.Join(temporaryDirectory, "peer-recipients")
	if err := os.WriteFile(peerRecipients, peer.Recipients, 0o600); err != nil {
		return err
	}
	pushBundle := filepath.Join(temporaryDirectory, "push.age")
	if _, err := transfer.Export(ctx, age, local, peerRecipients, pushBundle); err != nil {
		return fmt.Errorf("prepare push: %w", err)
	}
	pushed, err := client.Push(ctx, pushBundle)
	if err != nil {
		return fmt.Errorf("push: %w", err)
	}

	localRecipients, err := os.ReadFile(local.RecipientsPath)
	if err != nil {
		return err
	}
	pullBundle := filepath.Join(temporaryDirectory, "pull.age")
	if err := client.Pull(ctx, localRecipients, pullBundle); err != nil {
		return fmt.Errorf("pull: %w", err)
	}
	pulled, err := transfer.Import(ctx, age, local, pullBundle)
	result := syncResult{PeerFingerprint: peer.Fingerprint, Pushed: pushed, Pulled: pulled}
	if common.json {
		if jsonErr := writeJSON(stdout, result); jsonErr != nil {
			return errors.Join(err, jsonErr)
		}
	} else {
		fmt.Fprintf(stdout, "peer %s\n", peer.Fingerprint)
		fmt.Fprintf(stdout, "push: imported %d, skipped %d\n", pushed.Imported, pushed.Skipped)
		fmt.Fprintf(stdout, "pull: imported %d, skipped %d\n", pulled.Imported, pulled.Skipped)
	}
	return err
}

func runServe(ctx context.Context, arguments []string, input io.Reader, output io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	var common commonFlags
	addCommonFlags(flags, &common, stderr)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: pa-xfer serve")
	}
	age, err := agecmd.Find(common.age)
	if err != nil {
		return err
	}
	directory, err := filepath.Abs(common.store)
	if err != nil {
		return err
	}
	return remote.Serve(ctx, age, directory, input, output)
}

func openRuntime(common commonFlags) (agecmd.Tool, *store.Store, error) {
	age, err := agecmd.Find(common.age)
	if err != nil {
		return agecmd.Tool{}, nil, err
	}
	directory, err := filepath.Abs(common.store)
	if err != nil {
		return agecmd.Tool{}, nil, fmt.Errorf("resolve store directory: %w", err)
	}
	opened, err := store.Open(directory)
	if err != nil {
		return agecmd.Tool{}, nil, err
	}
	return age, opened, nil
}

func defaultStoreDir() string {
	if directory := os.Getenv("PA_DIR"); directory != "" {
		return directory
	}
	if dataHome := os.Getenv("XDG_DATA_HOME"); dataHome != "" {
		return filepath.Join(dataHome, "pa")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".local", "share", "pa")
	}
	return filepath.Join(home, ".local", "share", "pa")
}

func writeJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("write JSON result: %w", err)
	}
	return nil
}
