package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"pairfob/internal/admin"
)

const gateUsage = `usage: pairfob gate set [--password-stdin] | pairfob gate clear | pairfob gate status`

// maxGatePasswordRead bounds a --password-stdin read. The daemon rejects
// anything over 128 bytes anyway; the cap exists so a pipe that never ends
// cannot make the CLI buffer without limit.
const maxGatePasswordRead = 4096

func gateCommand(args []string, sock string) error {
	if len(args) == 0 {
		return errors.New(gateUsage)
	}
	switch args[0] {
	case "set":
		return gateSetCommand(args[1:], sock, os.Stdin, os.Stdout)
	case "clear":
		if len(args) != 1 {
			return errors.New(gateUsage)
		}
		return gateClearCommand(sock, os.Stdout)
	case "status":
		if len(args) != 1 {
			return errors.New(gateUsage)
		}
		return gateStatusCommand(sock, os.Stdout)
	default:
		return errors.New(gateUsage)
	}
}

// gateSetCommand reads the passphrase from stdin or an interactive prompt.
//
// There is deliberately no flag that takes the passphrase as an argument: a
// command line is visible to every process on the machine through ps and is
// written to the shell's history file.
func gateSetCommand(args []string, sock string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("gate set", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fromStdin := fs.Bool("password-stdin", false, "")
	if err := fs.Parse(args); err != nil {
		return errors.New(gateUsage)
	}
	if fs.NArg() != 0 {
		return errors.New("the passphrase cannot be passed as an argument; use --password-stdin or type it when prompted")
	}
	password, err := readGatePassword(*fromStdin, in, out)
	if err != nil {
		return err
	}
	resp, err := admin.Call(sock, admin.Request{Op: "gate.set", Password: password})
	if err != nil {
		return notRunning(err)
	}
	var status admin.GateStatus
	if len(resp.Result) > 0 && json.Unmarshal(resp.Result, &status) != nil {
		return errors.New("pairfob returned an invalid gate status")
	}
	_, err = fmt.Fprintf(out, "Pairing passphrase set. Open Pairfob on a device and type it to pair.\n")
	return err
}

func readGatePassword(fromStdin bool, in io.Reader, out io.Writer) (string, error) {
	if fromStdin {
		return readGatePasswordFrom(in)
	}
	return promptGatePassword(in, out)
}

// readGatePasswordFrom takes the first line of the reader. A trailing newline
// from `echo` or a heredoc is stripped here; any other surrounding whitespace
// is left for the daemon's normalizePassword, which is the single place that
// decides what a passphrase's bytes are.
func readGatePasswordFrom(in io.Reader) (string, error) {
	line, err := bufio.NewReader(io.LimitReader(in, maxGatePasswordRead)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	password := strings.TrimRight(line, "\r\n")
	if password == "" {
		return "", errors.New("no passphrase on stdin")
	}
	return password, nil
}

// promptGatePassword reads the passphrase twice with the terminal echo off.
// The confirmation matters more than usual here: a typo is not discovered at
// login time by the operator but by whoever tries to pair a phone later.
func promptGatePassword(in io.Reader, out io.Writer) (string, error) {
	file, ok := in.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return "", errors.New("no terminal to prompt on; use: pairfob gate set --password-stdin")
	}
	fd := int(file.Fd())
	if _, err := fmt.Fprint(out, "New pairing passphrase: "); err != nil {
		return "", err
	}
	first, err := term.ReadPassword(fd)
	if _, printErr := fmt.Fprintln(out); printErr != nil && err == nil {
		return "", printErr
	}
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	if _, err := fmt.Fprint(out, "Retype it: "); err != nil {
		return "", err
	}
	second, err := term.ReadPassword(fd)
	if _, printErr := fmt.Fprintln(out); printErr != nil && err == nil {
		return "", printErr
	}
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	if string(first) != string(second) {
		return "", errors.New("the two passphrases do not match")
	}
	return string(first), nil
}

// gateClearCommand revokes the passphrase. It reports in prose like the other
// gate subcommands, and says what pairing falls back to: clearing the gate
// leaves the computer reachable only through a one-use code, which is a
// surprise worth stating outright rather than implying with a bare ok.
func gateClearCommand(sock string, out io.Writer) error {
	if _, err := admin.Call(sock, admin.Request{Op: "gate.clear"}); err != nil {
		return notRunning(err)
	}
	_, err := fmt.Fprintln(out, "Pairing passphrase cleared. Devices already paired keep working; new ones need: pairfob pair")
	return err
}

// gateStatusCommand reports whether a gate exists and when it changed. It
// prints no passphrase and no verifier — only what an operator needs to tell
// "a gate is configured" from "pairing still needs a one-use code".
func gateStatusCommand(sock string, out io.Writer) error {
	resp, err := admin.Call(sock, admin.Request{Op: "gate.status"})
	if err != nil {
		return notRunning(err)
	}
	var status admin.GateStatus
	if json.Unmarshal(resp.Result, &status) != nil {
		return errors.New("pairfob returned an invalid gate status")
	}
	if !status.Configured {
		_, err := fmt.Fprintln(out, "No pairing passphrase is set. Pair with: pairfob pair")
		return err
	}
	if _, err := fmt.Fprintf(out, "Pairing passphrase is set.\n  pair_ref   %s\n", status.PairRef); err != nil {
		return err
	}
	if status.CreatedAt > 0 {
		if _, err := fmt.Fprintf(out, "  created    %s\n", lastSeenPhrase(status.CreatedAt)); err != nil {
			return err
		}
	}
	if status.UpdatedAt > 0 {
		if _, err := fmt.Fprintf(out, "  changed    %s\n", lastSeenPhrase(status.UpdatedAt)); err != nil {
			return err
		}
	}
	return nil
}
