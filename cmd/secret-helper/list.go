package main

import (
	"context"
	"fmt"

	"github.com/menta2l/secret-helper/pkg/secrets/google"
	"github.com/menta2l/secret-helper/pkg/secrets/vault"
)

func ListCmd(command string, args ...string) error {

	if opt.List.Provider == "" {
		return fmt.Errorf("Please specify --provider=[vault|google]")
	}
	switch opt.List.Provider {
	case "google":
		p, err := google.NewGoogleSecretsProvider(context.Background())
		if err != nil {
			return err
		}
		keys, err := p.ListSecrets(context.Background(), opt.List.Prefix)
		if err != nil {
			return err
		}
		for _, k := range keys {
			fmt.Println(k)
		}

	case "vault":
		p, err := vault.NewVaultSecretsProvider(context.Background())
		if err != nil {
			return err
		}
		keys, err := p.ListSecrets(context.Background(), opt.List.Prefix)
		if err != nil {
			return err
		}
		for _, k := range keys {
			fmt.Println(k)
		}
	default:
		// freebsd, openbsd,
		// plan9, windows...
		return fmt.Errorf("Unsupported provider %s", opt.List.Provider)
	}
	return nil
}
