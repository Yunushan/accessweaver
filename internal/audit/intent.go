package audit

import (
	"context"
	"sync/atomic"
)

type profileIntentKey struct{}
type profileIntent struct {
	action string
	active atomic.Bool
}

// ProfileIntentActive observes an in-process recorder capability. Request JSON,
// headers, environment and caller-selected context keys cannot create it. It is
// valid only during the synchronous callback after a durable observed intent,
// and is revoked before its terminal event. It authenticates no collector or
// human requester. Producers must not fork/reuse a callback for other operations.
func ProfileIntentActive(ctx context.Context, mutation string) bool {
	if ctx == nil {
		return false
	}
	intent, ok := ctx.Value(profileIntentKey{}).(*profileIntent)
	if !ok || intent == nil || !intent.active.Load() {
		return false
	}
	switch mutation {
	case "write":
		return intent.action == "profile.write" || intent.action == "profile.import"
	case "delete":
		return intent.action == "profile.delete"
	}
	return false
}
func callWithProfileIntent(ctx context.Context, action string, operation func(context.Context) OperationResult) OperationResult {
	intent := &profileIntent{action: action}
	intent.active.Store(true)
	defer intent.active.Store(false)
	return callRecordedOperation(context.WithValue(ctx, profileIntentKey{}, intent), operation)
}

// Mask any outer profile scope when another synchronous producer is nested.
// This does not revoke the outer callback's own still-active capability.
func callWithoutProfileIntent(ctx context.Context, operation func(context.Context) OperationResult) OperationResult {
	return callRecordedOperation(context.WithValue(ctx, profileIntentKey{}, (*profileIntent)(nil)), operation)
}
