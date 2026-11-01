package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

func managedCommand(args []string) error {
	if len(args) == 0 {
		fmt.Print("Managed configuration tools (native runtime enforcement is partial):\n  managed status\n  managed prepare ENVELOPE.json --public-key BASE64 --minimum-revision N --out INSTALLATION.json\n  managed validate POLICY.json\n  managed digest-profile PROFILE.json\n  managed digest-workflow REQUEST.json\n  managed sign POLICY.json --private-key PRIVATE-KEY.pem [--out ENVELOPE.json]\n  managed public-key --private-key PRIVATE-KEY.pem\n  managed verify ENVELOPE.json --public-key BASE64 [--minimum-revision N]\nSigning requires an offline Ed25519 PKCS#8 PEM key. Never deploy the private key.\n")
		return nil
	}
	switch args[0] {
	case "status":
		if len(args) != 1 {
			return errors.New("usage: managed status")
		}
		status, err := managed.MachineStatus()
		return errors.Join(err, printJSON(status))
	case "prepare":
		if len(args) != 8 || args[2] != "--public-key" || args[4] != "--minimum-revision" || args[6] != "--out" {
			return errors.New("usage: managed prepare ENVELOPE.json --public-key BASE64 --minimum-revision N --out INSTALLATION.json")
		}
		public, err := managed.PublicKey(args[3])
		if err != nil {
			return err
		}
		minimum, err := strconv.ParseUint(args[5], 10, 64)
		if err != nil {
			return errors.New("minimum revision must be a nonnegative integer")
		}
		data, err := readManagedFile(args[1], managed.MaxEnvelopeBytes)
		if err != nil {
			return err
		}
		installed, err := managed.PrepareInstallation(data, public, time.Now(), minimum)
		if err != nil {
			return err
		}
		return writeManagedOutput(args[7], installed)
	case "digest-profile", "digest-workflow":
		if len(args) != 2 {
			return errors.New("usage: managed digest-profile PROFILE.json | managed digest-workflow REQUEST.json")
		}
		data, err := readManagedFile(args[1], 1<<20)
		if err != nil {
			return err
		}
		var digest string
		if args[0] == "digest-profile" {
			p, decodeErr := profile.Decode(bytes.NewReader(data))
			if decodeErr != nil {
				return decodeErr
			}
			digest, err = p.ExecutionDigest()
		} else {
			decoder := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})))
			decoder.DisallowUnknownFields()
			var request workflow.Request
			if err := decoder.Decode(&request); err != nil {
				return err
			}
			var trailing any
			if err := decoder.Decode(&trailing); err != io.EOF {
				return errors.New("expected one workflow request")
			}
			digest, err = request.PolicyDigest()
		}
		if err != nil {
			return err
		}
		return printJSON(map[string]any{"inputSHA256": digest, "runtimeEnforced": false})
	case "validate":
		if len(args) != 2 {
			return errors.New("usage: managed validate POLICY.json")
		}
		data, err := readManagedFile(args[1], managed.MaxPolicyBytes)
		if err != nil {
			return err
		}
		policy, err := managed.DecodePolicy(data, time.Now(), 0)
		if err != nil {
			return err
		}
		return printJSON(policy)
	case "public-key":
		if len(args) != 3 || args[1] != "--private-key" {
			return errors.New("usage: managed public-key --private-key PRIVATE-KEY.pem")
		}
		private, err := readSigningKey(args[2])
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(os.Stdout, base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)))
		return err
	case "sign":
		if (len(args) != 4 && len(args) != 6) || args[2] != "--private-key" || len(args) == 6 && args[4] != "--out" {
			return errors.New("usage: managed sign POLICY.json --private-key PRIVATE-KEY.pem [--out ENVELOPE.json]")
		}
		payload, err := readManagedFile(args[1], managed.MaxPolicyBytes)
		if err != nil {
			return err
		}
		private, err := readSigningKey(args[3])
		if err != nil {
			return err
		}
		signed, err := managed.Sign(payload, private, time.Now())
		if err != nil {
			return err
		}
		if len(args) == 6 {
			// Exclusive creation prevents accidentally replacing a signing key,
			// policy source, or an existing reviewed envelope.
			return writeManagedOutput(args[5], signed)
		}
		_, err = os.Stdout.Write(signed)
		return err
	case "verify":
		if (len(args) != 4 && len(args) != 6) || args[2] != "--public-key" {
			return errors.New("usage: managed verify ENVELOPE.json --public-key BASE64 [--minimum-revision N]")
		}
		var minimum uint64
		if len(args) == 6 {
			if args[4] != "--minimum-revision" {
				return errors.New("expected --minimum-revision N")
			}
			var err error
			minimum, err = strconv.ParseUint(args[5], 10, 64)
			if err != nil {
				return errors.New("minimum revision must be a nonnegative integer")
			}
		}
		public, err := managed.PublicKey(args[3])
		if err != nil {
			return err
		}
		data, err := readManagedFile(args[1], managed.MaxEnvelopeBytes)
		if err != nil {
			return err
		}
		verified, err := managed.Verify(data, public, time.Now(), minimum)
		if err != nil {
			return err
		}
		return printJSON(verified)
	default:
		return errors.New("unknown managed configuration command; use managed for usage")
	}
}

func readManagedFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("managed input must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("managed input exceeds size limit")
	}
	return data, nil
}

func readSigningKey(path string) (ed25519.PrivateKey, error) {
	encoded, err := readManagedFile(path, 8<<10)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(encoded)
	block, rest := pem.Decode(trimmed)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN PRIVATE KEY-----")) || block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected one unencrypted Ed25519 PKCS#8 PRIVATE KEY PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("cannot parse Ed25519 PKCS#8 private key")
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signing key must be Ed25519")
	}
	return private, nil
}

func writeManagedOutput(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	return errors.Join(writeErr, syncErr, f.Close())
}
