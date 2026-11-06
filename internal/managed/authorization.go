package managed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Authorization retains only the authenticated policy identity and validity
// window. It cannot authorize new inputs or reuse permissions after a change.
type Authorization struct {
	guard                *Guard
	managed              bool
	keyID, payloadSHA256 string
	expiresAt            time.Time
}

const policyCheckInterval = time.Second

func newAuthorization(g *Guard, a *Authority) *Authorization {
	result := &Authorization{guard: g}
	if a != nil {
		result.managed = true
		result.keyID = a.verified.KeyID
		result.payloadSHA256 = a.verified.PayloadSHA256
		result.expiresAt = a.verified.Policy.ExpiresAt
	}
	return result
}

// Check also rejects enrollment/removal while a job runs. An unmanaged launch
// may have inherited an environment that is unsuitable for managed execution.
func (a *Authorization) Check() error {
	if a == nil {
		return fmt.Errorf("%w: operation has no retained authorization", ErrUnavailable)
	}
	if a.managed && !time.Now().Before(a.expiresAt) {
		return fmt.Errorf("%w: authorization expired; review and restart the operation", ErrDenied)
	}
	current, err := a.guard.authority()
	if err != nil {
		return fmt.Errorf("%w: active operation policy check failed: %w", ErrUnavailable, err)
	}
	if current == nil && !a.managed {
		return nil
	}
	if current == nil || !a.managed || current.verified.KeyID != a.keyID || current.verified.PayloadSHA256 != a.payloadSHA256 {
		return fmt.Errorf("%w: machine policy changed; review and restart the operation", ErrDenied)
	}
	return nil
}

// ReviewBinding is a stable opaque digest of this retained authority identity,
// after checking its current source and validity. It is review material only:
// possessing the digest grants no permission and cannot replace a fresh grant.
func (a *Authorization) ReviewBinding() (string, error) {
	if err := a.Check(); err != nil {
		return "", err
	}
	identity := struct {
		Managed       bool   `json:"managed"`
		KeyID         string `json:"keyId"`
		PayloadSHA256 string `json:"payloadSHA256"`
		ExpiresAt     string `json:"expiresAt"`
	}{a.managed, a.keyID, a.payloadSHA256, a.expiresAt.UTC().Format(time.RFC3339Nano)}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return "", fmt.Errorf("%w: review identity encoding failed: %w", ErrUnavailable, err)
	}
	digest := sha256.Sum256(append([]byte("AccessWeaver authorization review binding v1\x00"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

// Context checks before starting and then once per second, or at the retained
// expiry when sooner. Cancellation is terminal even if policy later recovers.
// Call cancel when the owned operation exits to release the monitor.
func (a *Authorization) Context(parent context.Context) (context.Context, context.CancelFunc, error) {
	if err := parent.Err(); err != nil {
		return nil, nil, err
	}
	if err := a.Check(); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithCancelCause(parent)
	go func() {
		for {
			delay := policyCheckInterval
			if a.managed {
				if remaining := time.Until(a.expiresAt); remaining < delay {
					delay = max(remaining, 0)
				}
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if ctx.Err() != nil {
				return
			}
			if err := a.Check(); err != nil {
				cancel(err)
				return
			}
		}
	}()
	return ctx, func() { cancel(context.Canceled) }, nil
}
