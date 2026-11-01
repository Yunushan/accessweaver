package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/Yunushan/accessweaver/internal/diagnostics"
)

func doctorRequest(args []string) (diagnostics.Request, error) {
	var input diagnostics.Request
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&input.Path, "path", "direct", "direct, socks5 or http-connect")
	flags.StringVar(&input.Transport, "transport", "tcp", "tcp or stun")
	flags.StringVar(&input.Proxy, "proxy", "", "proxy host:port (no credentials)")
	flags.IntVar(&input.Port, "port", 443, "target port")
	flags.IntVar(&input.TimeoutSeconds, "timeout", 5, "whole probe timeout in seconds")
	flags.BoolVar(&input.TLS, "tls", true, "verify target TLS certificate")
	if err := flags.Parse(args); err != nil {
		return input, err
	}
	if flags.NArg() > 1 {
		return input, errors.New("usage: accessweaver doctor [options] [HOST]")
	}
	input.Host = "discord.com"
	if flags.NArg() == 1 {
		input.Host = flags.Arg(0)
	}
	if input.Transport == "stun" {
		if flags.NArg() != 1 {
			return input, errors.New("STUN requires an explicit target HOST")
		}
		// Transport defaults are explicit and overridden only by flags the user set.
		tlsSet, portSet := false, false
		flags.Visit(func(f *flag.Flag) { tlsSet = tlsSet || f.Name == "tls"; portSet = portSet || f.Name == "port" })
		if !tlsSet {
			input.TLS = false
		}
		if !portSet {
			input.Port = 3478
		}
	}
	return input, nil
}
func doctorCommand(args []string) error {
	input, err := doctorRequest(args)
	if errors.Is(err, flag.ErrHelp) {
		_, err = io.WriteString(os.Stdout, "Usage: accessweaver doctor [--path direct|socks5|http-connect] [--proxy HOST:PORT] [--transport tcp|stun] [--port N] [--timeout 1..60] [--tls=true|false] [HOST]\nSTUN requires an explicit server; flags precede HOST.\n")
		return err
	}
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	report, err := diagnostics.Diagnose(ctx, input, nil)
	if err != nil {
		return err
	}
	if err := printJSON(report); err != nil {
		return err
	}
	if !report.Passed() {
		return errors.New("one or more requested diagnostic checks failed")
	}
	return nil
}
