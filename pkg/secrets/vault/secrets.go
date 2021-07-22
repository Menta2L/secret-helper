package vault

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/menta2l/secret-helper/auth"
	"github.com/menta2l/secret-helper/pkg/secrets"
	"github.com/menta2l/secret-helper/vault"
)

// SecretsProvider Google Cloud secrets provider
type SecretsProvider struct {
	ctx   context.Context
	cfg   VaultConfig
	Token string
}
type VaultConfig struct {
	Url      string
	Method   string
	Token    string
	Username string
	Path     string
	Password string
	Mount    string
	Insecure bool
}

func NewVaultSecretsProvider(ctx context.Context) (secrets.Provider, error) {
	if _, ok := os.LookupEnv("VAULT_APPLICATION_CREDENTIALS"); !ok {
		return nil, fmt.Errorf("enveroment variable VAULT_APPLICATION_CREDENTIALS must be set")
	}
	cfgFile := os.Getenv("VAULT_APPLICATION_CREDENTIALS")
	if cfgFile == "" {
		return nil, fmt.Errorf("enveroment variable VAULT_APPLICATION_CREDENTIALS cannot be empty")
	}
	if _, err := os.Stat(cfgFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("enveroment variable VAULT_APPLICATION_CREDENTIALS file not exist")
	}
	file, err := ioutil.ReadFile(cfgFile)
	if err != nil {
		return nil, err
	}
	data := VaultConfig{}

	err = json.Unmarshal([]byte(file), &data)
	if err != nil {
		return nil, err
	}
	os.Setenv("VAULT_ADDR", data.Url)
	sp := SecretsProvider{}
	sp.ctx = ctx
	sp.cfg = data
	err = sp.auth()
	if err != nil {
		return nil, err
	}
	return &sp, nil
}
func (sp SecretsProvider) ListSecrets(ctx context.Context, prefix string) ([]string, error) {
	if prefix == "" {
		return nil, fmt.Errorf("--prefix is required")
	}
	v := connect(true)
	path := fmt.Sprintf("%s/%s", sp.cfg.Mount, prefix)
	s, err := v.Read(path)
	if err != nil {
		return nil, err
	}
	return s.Keys(), nil
	/*
		results := make(map[string]string, 0)

		for _, key := range s.Keys() {
			results[key] = s.Get(key)
			fmt.Printf("%s %s\n", key, results[key])
		}

		return []string{}, nil
	*/
}
func (sp SecretsProvider) GetSecret(ctx context.Context, prefix string, key string) (string, error) {
	if prefix == "" {
		return "", fmt.Errorf("--prefix is required")
	}
	v := connect(true)
	path := fmt.Sprintf("%s/%s", sp.cfg.Mount, prefix)
	s, err := v.Read(path)
	if err != nil {
		return "", err
	}
	return s.Get(key), nil
}
func (sp SecretsProvider) GetSecrets(ctx context.Context, preffix string) ([]string, error) {
	var envs []string
	return envs, nil
}
func (sp SecretsProvider) auth() error {
	var token string
	var err error

	switch sp.cfg.Method {
	case "token":
		if sp.cfg.Token == "" {
			return fmt.Errorf("token should be set when using token authentication")
		}
		token = sp.cfg.Token

	case "userpass":
		if sp.cfg.Username == "" || sp.cfg.Password == "" {
			return fmt.Errorf("username and password  should be set when using userpass authentication")
		}

		token, err = auth.UserPass(sp.cfg.Url, sp.cfg.Path, sp.cfg.Username, sp.cfg.Password)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unrecognized authentication method '%s'", sp.cfg.Method)
	}
	sp.Token = token
	os.Setenv("VAULT_TOKEN", token)

	return nil
}
func connect(auth bool) *vault.Vault {
	var caCertPool *x509.CertPool
	if os.Getenv("VAULT_CACERT") != "" {
		contents, err := ioutil.ReadFile(os.Getenv("VAULT_CACERT"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "@R{!! Could not read CA certificates: %s}", err.Error())
		}

		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(contents)
	}

	shouldSkipVerify := func() bool {
		skipVerifyVal := os.Getenv("VAULT_SKIP_VERIFY")
		if skipVerifyVal != "" && skipVerifyVal != "false" {
			return true
		}
		return false
	}

	conf := vault.VaultConfig{
		URL:        getVaultURL(),
		Token:      os.Getenv("VAULT_TOKEN"),
		Namespace:  os.Getenv("VAULT_NAMESPACE"),
		SkipVerify: shouldSkipVerify(),
		CACerts:    caCertPool,
	}

	if auth && conf.Token == "" {
		fmt.Fprintf(os.Stderr, "@R{You are not authenticated to a Vault.}\n")
		fmt.Fprintf(os.Stderr, "Try @C{safe auth ldap}\n")
		fmt.Fprintf(os.Stderr, " or @C{safe auth github}\n")
		fmt.Fprintf(os.Stderr, " or @C{safe auth token}\n")
		fmt.Fprintf(os.Stderr, " or @C{safe auth userpass}\n")
		fmt.Fprintf(os.Stderr, " or @C{safe auth approle}\n")
		os.Exit(1)
	}

	v, err := vault.NewVault(conf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "@R{!! %s}\n", err)
		os.Exit(1)
	}
	return v
}
func getVaultURL() string {
	ret := os.Getenv("VAULT_ADDR")
	if ret == "" {
		fmt.Fprintf(os.Stderr, "@R{You are not targeting a Vault.}\n")
		fmt.Fprintf(os.Stderr, "Try @C{safe target https://your-vault alias}\n")
		fmt.Fprintf(os.Stderr, " or @C{safe target alias}\n")
		os.Exit(1)
	}
	return ret
}

//00000000-0000-0000-0000-000000000000
