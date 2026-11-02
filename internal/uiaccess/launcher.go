// Package uiaccess delivers a dashboard credential through an OS-private file.
// The credential is never passed in a process argument or an unauthenticated API.
package uiaccess

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"html"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type Launcher struct {
	URL, Path string
	directory string
}

func New(address, token string) (*Launcher, error) {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid dashboard listener address")
	}
	if len(token) != 43 || strings.Trim(token, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
		return nil, errors.New("invalid dashboard session credential")
	}
	if err = RequireUnelevated(); err != nil {
		return nil, err
	}
	parent, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(parent, 0700); err != nil {
		return nil, err
	}
	parent, err = filepath.EvalSymlinks(parent)
	if err != nil {
		return nil, err
	}
	if err = checkParents(parent); err != nil {
		return nil, err
	}
	var directory string
	for range 16 {
		id := make([]byte, 16)
		if _, err = rand.Read(id); err != nil {
			return nil, err
		}
		directory = filepath.Join(parent, "accessweaver-ui-"+hex.EncodeToString(id))
		err = createPrivateDirectory(directory)
		if os.IsExist(err) {
			continue
		}
		break
	}
	if err != nil {
		return nil, err
	}
	launcher := &Launcher{Path: filepath.Join(directory, "start.html"), directory: directory}
	u.Fragment = "accessweaver-session=" + token
	target := html.EscapeString(u.String())
	page := "<!doctype html><meta charset=utf-8><meta name=referrer content=no-referrer><meta http-equiv=Content-Security-Policy content=\"default-src 'none'; base-uri 'none'; form-action 'none'\"><meta http-equiv=refresh content=\"0;url=" + target + "\"><title>AccessWeaver</title><a href=\"" + target + "\">Open AccessWeaver</a>"
	f, err := createPrivateFile(launcher.Path)
	if err != nil {
		_ = launcher.Close()
		return nil, err
	}
	_, writeErr := f.WriteString(page)
	closeErr := f.Close()
	if writeErr != nil {
		_ = launcher.Close()
		return nil, writeErr
	}
	if closeErr != nil {
		_ = launcher.Close()
		return nil, closeErr
	}
	path := filepath.ToSlash(launcher.Path)
	fileURL := url.URL{Scheme: "file"}
	if strings.HasPrefix(path, "//") {
		parts := strings.SplitN(strings.TrimPrefix(path, "//"), "/", 2)
		fileURL.Host = parts[0]
		if len(parts) > 1 {
			fileURL.Path = "/" + parts[1]
		}
	} else {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		fileURL.Path = path
	}
	launcher.URL = fileURL.String()
	return launcher, nil
}

func (l *Launcher) Close() error { return os.RemoveAll(l.directory) }
