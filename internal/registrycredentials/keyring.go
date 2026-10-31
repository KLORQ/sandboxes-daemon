package registrycredentials

import (
	"context"
	"errors"

	keyring "github.com/zalando/go-keyring"
)

// NativeVault stores secrets in macOS Keychain, Windows Credential Manager,
// or Linux Secret Service. It never falls back to plaintext files.
type NativeVault struct{ backend keyringBackend }

type keyringBackend interface {
	Set(service, account, secret string) error
	Get(service, account string) (string, error)
	Delete(service, account string) error
}

type systemKeyring struct{}

func (systemKeyring) Get(service, account string) (string, error) {
	return keyring.Get(service, account)
}

func (systemKeyring) Set(service, account, secret string) error {
	return keyring.Set(service, account, secret)
}

func (systemKeyring) Delete(service, account string) error {
	return keyring.Delete(service, account)
}

func (v NativeVault) Set(ctx context.Context, service, account, secret string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return v.keyringBackend().Set(service, account, secret)
}

func (v NativeVault) Get(ctx context.Context, service, account string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	secret, err := v.keyringBackend().Get(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrNotFound
	}
	return secret, err
}

func (v NativeVault) Delete(ctx context.Context, service, account string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := v.keyringBackend().Delete(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

func (v NativeVault) keyringBackend() keyringBackend {
	if v.backend != nil {
		return v.backend
	}
	return systemKeyring{}
}
