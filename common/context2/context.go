package context2

import (
	"context"
	"time"
)

// WithDeadline returns a derived context that points to the parent context
// but force set the deadline to d.
//
// The returned [Context.Done] channel is closed when the deadline expires,
// when the parent cancel function is called, when the returned cancel function is called.
//
// Canceling this context releases resources associated with it, so code should
// call cancel as soon as the operations running in this [Context] complete.
func WithDeadline(parent context.Context, d time.Time) (context.Context, context.CancelFunc) {
	if _, ok := parent.Deadline(); !ok { // no parent deadline is set
		return context.WithDeadline(parent, d)
	}

	// remove the parent deadline and set the new one
	ctx, cancel := context.WithDeadline(context.WithoutCancel(parent), d)

	go func() {
		select {
		case <-parent.Done():
			if parent.Err() == context.Canceled { // cancel by parent call the cancel function
				cancel()
			}
		case <-ctx.Done():
		}
	}()

	return ctx, cancel
}

// WithTimeout returns WithDeadline(parent, time.Now().Add(timeout)).
//
// Canceling this context releases resources associated with it, so code should
// call cancel as soon as the operations running in this [Context] complete.
func WithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return WithDeadline(parent, time.Now().Add(timeout))
}
