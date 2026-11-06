package profile

import (
	"context"
	"errors"
)

// ErrMutationUncertain means an accepted mutation's effects or final cleanup
// cannot be confirmed. Inspect saved profiles before deciding on another edit;
// neither this marker nor its private causes authorize replay or rollback.
var ErrMutationUncertain = errors.New("profile mutation completion could not be confirmed; inspect saved profiles before retrying")

type mutationFailure struct{ cause error }

func (e *mutationFailure) Error() string   { return ErrMutationUncertain.Error() }
func (e *mutationFailure) Unwrap() []error { return []error{ErrMutationUncertain, e.cause} }

// One instance belongs to one accepted lease and is mandatory at every source
// effect boundary, including all Seed samples and its marker. It is sticky and
// conservative: an attempted effect is not proof of publication or durability.
// It is never shared through Store, context, globals or a runtime selector.
type mutationProgress struct{ effectsAttempted bool }

// Cleanup is installed before the body, including on panic. Native I/O remains
// synchronous; cancellation cannot abandon an owned lease. Preserve the exact
// primary only before effects with clean context/Close. Body panic propagates
// unchanged after actual cleanup; a recovering caller must treat it as unknown.
func mutateProfileSynchronously(ctx context.Context, body func(context.Context, *mutationProgress) error, closeLease func() error) (failure error) {
	var progress mutationProgress
	defer func() {
		closeErr := closeLease()
		canceled := ctx.Err()
		if closeErr != nil || canceled != nil || (failure != nil && progress.effectsAttempted) {
			failure = &mutationFailure{cause: errors.Join(failure, canceled, closeErr)}
		}
	}()
	return body(ctx, &progress)
}
