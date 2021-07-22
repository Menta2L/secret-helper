package main

import (
	"context"
	"fmt"

	"github.com/menta2l/secret-helper/pkg/secrets/google"
	"github.com/menta2l/secret-helper/pkg/secrets/vault"
)

func GetCmd(command string, args ...string) error {

	if opt.Get.Provider == "" {
		return fmt.Errorf("please specify --provider=[vault|google]")
	}
	switch opt.Get.Provider {
	case "google":
		p, err := google.NewGoogleSecretsProvider(context.Background())
		if err != nil {
			return err
		}
		val, err := p.GetSecret(context.Background(), opt.Get.Prefix, args[0])
		if err != nil {
			return err
		}
		fmt.Printf("%s=%s\n", args[0], val)

	case "vault":
		p, err := vault.NewVaultSecretsProvider(context.Background())
		if err != nil {
			return err
		}
		val, err := p.GetSecret(context.Background(), opt.Get.Prefix, args[0])
		if err != nil {
			return err
		}
		fmt.Printf("%s=%s\n", args[0], val)
	default:
		return fmt.Errorf("unsupported provider %s", opt.Get.Provider)
	}
	return nil
}
