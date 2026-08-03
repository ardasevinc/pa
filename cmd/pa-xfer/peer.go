package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/ardasevinc/pa/internal/peerregistry"
	"github.com/ardasevinc/pa/internal/remote"
	"github.com/ardasevinc/pa/internal/store"
)

type peerFlags struct {
	store string
	json  bool
}

func addPeerFlags(flags *flag.FlagSet, values *peerFlags, stderr io.Writer) {
	flags.SetOutput(stderr)
	flags.StringVar(&values.store, "store", defaultStoreDir(), "pa data directory")
	flags.BoolVar(&values.json, "json", false, "emit JSON")
}

func runPeer(ctx context.Context, arguments []string, input io.Reader, interactive bool, stdout, stderr io.Writer) error {
	if len(arguments) == 0 || strings.HasPrefix(arguments[0], "-") {
		return runPeerProbe(ctx, arguments, stdout, stderr)
	}
	switch arguments[0] {
	case "add":
		return runPeerAdd(ctx, arguments[1:], input, interactive, stdout, stderr)
	case "list":
		return runPeerList(arguments[1:], stdout, stderr)
	case "show":
		return runPeerShow(arguments[1:], stdout, stderr)
	case "replace":
		return runPeerReplace(ctx, arguments[1:], input, interactive, stdout, stderr)
	case "remove":
		return runPeerRemove(arguments[1:], input, interactive, stdout, stderr)
	case "probe":
		return runPeerProbe(ctx, arguments[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown peer command %q", arguments[0])
	}
}

func runPeerAdd(ctx context.Context, arguments []string, input io.Reader, interactive bool, stdout, stderr io.Writer) error {
	name, remaining, err := peerNameArgument("add", arguments)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("peer add", flag.ContinueOnError)
	var common peerFlags
	var host, fingerprint, sshPath string
	addPeerFlags(flags, &common, stderr)
	flags.StringVar(&host, "host", name, "SSH destination (default: peer name)")
	flags.StringVar(&fingerprint, "fingerprint", "", "independently verified recipient fingerprint")
	flags.StringVar(&sshPath, "ssh", "", "ssh executable for this invocation")
	if err := flags.Parse(remaining); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: pa-xfer peer add NAME [options]")
	}
	if err := validateProposedPeer(name, host, fingerprint); err != nil {
		return err
	}
	registry, closeRegistry, err := openPeerRegistry(common.store)
	if err != nil {
		return err
	}
	defer closeRegistry()
	if _, err := registry.Get(name); err == nil {
		return fmt.Errorf("peer %q already exists; use `pa-xfer peer replace %s`", name, name)
	} else if !errors.Is(err, peerregistry.ErrNotFound) {
		return err
	}
	observed, err := (remote.Client{Host: host, SSHPath: sshPath}).Recipient(ctx)
	if err != nil {
		return err
	}
	record := peerregistry.Record{Version: peerregistry.Version, Name: name, Host: host, Fingerprint: observed.Fingerprint}
	if err := authorizePeer("add", record, nil, fingerprint, input, interactive, common.json, stderr); err != nil {
		return err
	}
	if err := registry.Add(record); err != nil {
		return err
	}
	if common.json {
		return writeJSON(stdout, record)
	}
	fmt.Fprintf(stdout, "saved peer %q\n", name)
	return nil
}

func runPeerList(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("peer list", flag.ContinueOnError)
	var common peerFlags
	addPeerFlags(flags, &common, stderr)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: pa-xfer peer list [options]")
	}
	registry, closeRegistry, err := openPeerRegistry(common.store)
	if err != nil {
		return err
	}
	defer closeRegistry()
	records, err := registry.List()
	if err != nil {
		return err
	}
	if common.json {
		return writeJSON(stdout, records)
	}
	if len(records) == 0 {
		_, err := io.WriteString(stdout, "no peers\n")
		return err
	}
	for _, record := range records {
		fmt.Fprintf(stdout, "%s\t%s\t%s\n", record.Name, record.Host, record.Fingerprint)
	}
	return nil
}

func runPeerShow(arguments []string, stdout, stderr io.Writer) error {
	name, remaining, err := peerNameArgument("show", arguments)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("peer show", flag.ContinueOnError)
	var common peerFlags
	addPeerFlags(flags, &common, stderr)
	if err := flags.Parse(remaining); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: pa-xfer peer show NAME [options]")
	}
	registry, closeRegistry, err := openPeerRegistry(common.store)
	if err != nil {
		return err
	}
	defer closeRegistry()
	record, err := registry.Get(name)
	if err != nil {
		return err
	}
	return writePeer(stdout, record, common.json)
}

func runPeerReplace(ctx context.Context, arguments []string, input io.Reader, interactive bool, stdout, stderr io.Writer) error {
	name, remaining, err := peerNameArgument("replace", arguments)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("peer replace", flag.ContinueOnError)
	var common peerFlags
	var host, fingerprint, sshPath string
	addPeerFlags(flags, &common, stderr)
	flags.StringVar(&host, "host", "", "new SSH destination (default: current host)")
	flags.StringVar(&fingerprint, "fingerprint", "", "independently verified new recipient fingerprint")
	flags.StringVar(&sshPath, "ssh", "", "ssh executable for this invocation")
	if err := flags.Parse(remaining); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: pa-xfer peer replace NAME [options]")
	}
	registry, closeRegistry, err := openPeerRegistry(common.store)
	if err != nil {
		return err
	}
	defer closeRegistry()
	current, err := registry.Get(name)
	if err != nil {
		return err
	}
	if host == "" {
		host = current.Host
	}
	if err := validateProposedPeer(name, host, fingerprint); err != nil {
		return err
	}
	observed, err := (remote.Client{Host: host, SSHPath: sshPath}).Recipient(ctx)
	if err != nil {
		return err
	}
	replacement := peerregistry.Record{Version: peerregistry.Version, Name: name, Host: host, Fingerprint: observed.Fingerprint}
	if fingerprint != "" && fingerprint != replacement.Fingerprint {
		return fmt.Errorf("supplied fingerprint %s does not match observed peer fingerprint %s", fingerprint, replacement.Fingerprint)
	}
	if replacement == current {
		if common.json {
			return writeJSON(stdout, replacement)
		}
		fmt.Fprintf(stdout, "peer %q is unchanged\n", name)
		return nil
	}
	if err := authorizePeer("replace", replacement, &current, fingerprint, input, interactive, common.json, stderr); err != nil {
		return err
	}
	if err := registry.Replace(current, replacement); err != nil {
		return err
	}
	if common.json {
		return writeJSON(stdout, replacement)
	}
	fmt.Fprintf(stdout, "replaced peer %q\n", name)
	return nil
}

func runPeerRemove(arguments []string, input io.Reader, interactive bool, stdout, stderr io.Writer) error {
	name, remaining, err := peerNameArgument("remove", arguments)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("peer remove", flag.ContinueOnError)
	var common peerFlags
	var yes bool
	addPeerFlags(flags, &common, stderr)
	flags.BoolVar(&yes, "yes", false, "confirm removal without prompting")
	if err := flags.Parse(remaining); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: pa-xfer peer remove NAME [--yes] [options]")
	}
	registry, closeRegistry, err := openPeerRegistry(common.store)
	if err != nil {
		return err
	}
	defer closeRegistry()
	record, err := registry.Get(name)
	if err != nil {
		return err
	}
	if !yes {
		if common.json || !interactive {
			return errors.New("peer remove requires --yes outside an interactive terminal")
		}
		fmt.Fprintf(stderr, "remove peer %q?\n\nhost: %s\nfingerprint: %s\n\ntype %q to confirm: ", name, record.Host, record.Fingerprint, "remove "+name)
		if err := readConfirmation(input, "remove "+name); err != nil {
			return err
		}
	}
	if err := registry.Remove(record); err != nil {
		return err
	}
	if common.json {
		return writeJSON(stdout, struct {
			Removed peerregistry.Record `json:"removed"`
		}{Removed: record})
	}
	fmt.Fprintf(stdout, "removed peer %q\n", name)
	return nil
}

func peerNameArgument(command string, arguments []string) (string, []string, error) {
	if len(arguments) == 0 || strings.HasPrefix(arguments[0], "-") {
		return "", nil, fmt.Errorf("usage: pa-xfer peer %s NAME [options]", command)
	}
	if err := peerregistry.ValidateName(arguments[0]); err != nil {
		return "", nil, err
	}
	return arguments[0], arguments[1:], nil
}

func validateProposedPeer(name, host, fingerprint string) error {
	if err := peerregistry.ValidateName(name); err != nil {
		return err
	}
	if err := remote.ValidateHost(host); err != nil {
		return err
	}
	if fingerprint != "" {
		return peerregistry.ValidateFingerprint(fingerprint)
	}
	return nil
}

func authorizePeer(action string, record peerregistry.Record, previous *peerregistry.Record, supplied string, input io.Reader, interactive, jsonOutput bool, stderr io.Writer) error {
	if supplied != "" {
		if supplied != record.Fingerprint {
			return fmt.Errorf("supplied fingerprint %s does not match observed peer fingerprint %s", supplied, record.Fingerprint)
		}
		return nil
	}
	if jsonOutput || !interactive {
		return fmt.Errorf("peer %s requires --fingerprint outside an interactive terminal", action)
	}
	fmt.Fprintf(stderr, "%s peer %q\n\nhost: %s\n", action, record.Name, record.Host)
	if previous != nil {
		fmt.Fprintf(stderr, "old fingerprint: %s\n", previous.Fingerprint)
	}
	fmt.Fprintf(stderr, "new fingerprint: %s\n\nverify this on the peer with `pa-xfer recipient`\ntype %q to confirm: ", record.Fingerprint, action+" "+record.Name)
	return readConfirmation(input, action+" "+record.Name)
}

func readConfirmation(input io.Reader, expected string) error {
	line, err := bufio.NewReader(input).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if line != expected {
		return errors.New("confirmation did not match; no peer trust was changed")
	}
	return nil
}

func openPeerRegistry(storeDirectory string) (*peerregistry.Registry, func() error, error) {
	directory, err := filepath.Abs(storeDirectory)
	if err != nil {
		return nil, func() error { return nil }, fmt.Errorf("resolve store directory: %w", err)
	}
	opened, err := store.Open(directory)
	if err != nil {
		return nil, func() error { return nil }, err
	}
	registry, err := peerregistry.Open(opened)
	if err != nil {
		_ = opened.Close()
		return nil, func() error { return nil }, err
	}
	return registry, func() error { return errors.Join(registry.Close(), opened.Close()) }, nil
}

func writePeer(output io.Writer, record peerregistry.Record, jsonOutput bool) error {
	if jsonOutput {
		return writeJSON(output, record)
	}
	fmt.Fprintf(output, "name: %s\nhost: %s\nfingerprint: %s\nversion: %d\n", record.Name, record.Host, record.Fingerprint, record.Version)
	return nil
}
