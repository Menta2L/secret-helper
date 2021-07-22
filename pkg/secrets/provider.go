package secrets

import "context"

// Provider secrets provider interface
type Provider interface {
	ListSecrets(ctx context.Context, preffix string) ([]string, error)
	GetSecret(ctx context.Context, preffix string, key string) (string, error)
	GetSecrets(ctx context.Context, preffix string) ([]string, error)
}
