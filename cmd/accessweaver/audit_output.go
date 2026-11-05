package main

import (
	"os"
	"os/signal"
	"syscall"
)

// Standard-output/error EPIPE otherwise terminates a Unix Go process before
// Write returns. Audit producers need that error to withhold dispatch or retain
// the conservative outcome; foreground engine launch needs it to clean up its
// owned process after a failed launch notice. Desktop startup and shutdown
// feedback use the same scope so a broken output cannot abandon owned work. Scope registration and restore
// the prior signal behavior without resetting other subscribers.
func observeAuditOutputPipes() func() {
	notifications := make(chan os.Signal, 1)
	signal.Notify(notifications, syscall.SIGPIPE)
	return func() { signal.Stop(notifications) }
}
