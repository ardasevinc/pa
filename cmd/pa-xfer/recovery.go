package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/ardasevinc/pa/internal/recovery"
)

func runBackups(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("backups", flag.ContinueOnError)
	flags.SetOutput(stderr)
	storeDirectory := flags.String("store", defaultStoreDir(), "pa data directory")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: pa-xfer backups [options]")
	}
	directory, err := filepath.Abs(*storeDirectory)
	if err != nil {
		return err
	}
	backups, err := recovery.List(directory)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return writeJSON(stdout, backups)
	}
	if len(backups) == 0 {
		_, err := io.WriteString(stdout, "no backups\n")
		return err
	}
	for _, backup := range backups {
		fmt.Fprintf(stdout, "%s\tbefore=%t\tafter=%t\treceipt=%t\n", backup.TransactionID, backup.Before, backup.After, backup.Receipt)
	}
	return nil
}

func runRestore(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("restore", flag.ContinueOnError)
	var common commonFlags
	var transactionID, phase string
	var confirmed, allowDirty bool
	addCommonFlags(flags, &common, stderr)
	flags.StringVar(&transactionID, "transaction", "", "source backup transaction")
	flags.StringVar(&phase, "phase", "before", "source phase: before or after")
	flags.BoolVar(&confirmed, "yes", false, "confirm replacing the live entry set")
	flags.BoolVar(&allowDirty, "allow-dirty", false, "continue an interrupted restore after reviewing dirty Git state")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if transactionID == "" || !confirmed || flags.NArg() != 0 {
		return errors.New("usage: pa-xfer restore --transaction ID --yes [--phase before|after] [options]")
	}
	age, destination, err := openRuntime(common)
	if err != nil {
		return err
	}
	defer destination.Close()
	result, restoreErr := recovery.RestoreWithOptions(ctx, age, destination, transactionID, phase, recovery.RestoreOptions{AllowDirty: allowDirty})
	if common.json {
		if err := writeJSON(stdout, result); err != nil {
			return errors.Join(restoreErr, err)
		}
	} else if result.TransactionID != "" {
		fmt.Fprintf(stdout, "restored %d, removed %d (transaction %s)\n", result.Restored, result.Removed, result.TransactionID)
		if result.Receipt != "" {
			fmt.Fprintf(stdout, "receipt: %s\n", result.Receipt)
		}
	}
	return restoreErr
}
