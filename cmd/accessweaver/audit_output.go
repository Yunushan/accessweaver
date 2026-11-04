package main

import (
	"os"
	"os/signal"
	"syscall"
)

// Standard-output/error EPIPE otherwise terminates a Unix Go process before
// Write returns. Audit producers need that error to withhold dispatch or retain
// the conservative outcome. Scope the registration to the command and restore
// the prior signal behavior without resetting other subscribers.
func observeAuditOutputPipes() func() {
	notifications := make(chan os.Signal, 1)
	signal.Notify(notifications, syscall.SIGPIPE)
	return func() { signal.Stop(notifications) }
}
