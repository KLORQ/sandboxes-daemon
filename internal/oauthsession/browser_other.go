//go:build !darwin

package oauthsession

import (
	"context"
	"errors"
)

// OpenBrowser is not supported on this platform yet.
func OpenBrowser(context.Context, string) error {
	return errors.New("OAuth browser launch is unsupported on this platform")
}
