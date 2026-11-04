package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"runtime"
	"strings"

	"github.com/Yunushan/accessweaver/internal/buildinfo"
)

var ErrProcessIdentity = errors.New("audit process identity or build metadata is unavailable")

type processPrincipal struct{ kind, value, class string }

// ProcessProducer reads the executing OS principal and this build's metadata.
// It does not identify an HTTP requester, an earlier elevating user, or a human.
// It grants no authority and does not authenticate the resulting wire claims.
//
// actorKey must be a dedicated, independently enrolled random 32-byte secret,
// protected separately from exported checkpoints. It pseudonymizes a UID/SID;
// it is not a signing key or an authentication credential. Keys/identities and
// raw OS errors are never included in the result or error. No account-name,
// directory-service, environment-identity or network lookup is performed.
//
// Recreate this metadata before recording an operation; changed principals,
// elevation, builds or keys require a separately enrolled stream. OS credentials
// must not be changed concurrently with recording. The caller must retain and
// authenticate the key/stream association and account for UID reuse and namespaces.
func ProcessProducer(actorKey [32]byte) (Producer, error) {
	if actorKey == ([32]byte{}) {
		return Producer{}, ErrProcessIdentity
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	principal, err := currentProcessPrincipal()
	if err != nil {
		return Producer{}, ErrProcessIdentity
	}
	return producerForProcess(actorKey, principal, buildinfo.Current())
}

func producerForProcess(key [32]byte, principal processPrincipal, info buildinfo.Info) (Producer, error) {
	if key == ([32]byte{}) || principal.value == "" || len(principal.value) > 256 || strings.ContainsRune(principal.value, 0) {
		return Producer{}, ErrProcessIdentity
	}
	switch info.Platform {
	case "windows":
		if principal.kind != "sid" {
			return Producer{}, ErrProcessIdentity
		}
	case "linux", "darwin", "freebsd", "openbsd":
		if principal.kind != "uid" {
			return Producer{}, ErrProcessIdentity
		}
	default:
		return Producer{}, ErrProcessIdentity
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(domain + "process-actor\x00" + info.Platform + "\x00" + principal.kind + "\x00" + principal.value))
	result := Producer{principal.class, hex.EncodeToString(mac.Sum(nil)), info.Commit, info.SourceState, info.Platform + "/" + info.Arch}
	if !validProducer(result) {
		return Producer{}, ErrProcessIdentity
	}
	return result, nil
}
