package main

import (
	"crypto/x509"
	"io/ioutil"
	"os"
	"strings"

	fmt "github.com/jhunt/go-ansi"
	"github.com/menta2l/secret-helper/vault"

	"github.com/jhunt/go-cli"
	env "github.com/jhunt/go-envirotron"
)

var Version string
var r *Runner
var opt Options

func main() {

	//opt.Gen.Policy = "a-zA-Z0-9"

	opt.Clobber = true

	go Signals()
	r = NewRunner()
	r.Dispatch("version", &Help{
		Summary: "Print the version of the secret-helper CLI",
		Usage:   "secret-helper version",
		Type:    AdministrativeCommand,
	}, func(command string, args ...string) error {
		if Version != "" {
			fmt.Fprintf(os.Stderr, "secret-helper v%s\n", Version)
		} else {
			fmt.Fprintf(os.Stderr, "secret-helper (development build)\n")
		}
		os.Exit(0)
		return nil
	})
	r.Dispatch("help", nil, func(command string, args ...string) error {
		if len(args) == 0 {
			args = append(args, "commands")
		}
		r.Help(os.Stderr, strings.Join(args, " "))
		os.Exit(0)
		return nil
	})
	r.Dispatch("envvars", nil, func(command string, args ...string) error {
		fmt.Printf(`@G{[SCRIPTING]}
  @B{SAFE_TARGET}    The vault alias which requests are sent to.
@G{[PROXYING]}
  @B{HTTP_PROXY}     The proxy to use for HTTP requests.
  @B{HTTPS_PROXY}    The proxy to use for HTTPS requests.
  @B{SAFE_ALL_PROXY} The proxy to use for both HTTP and HTTPS requests.
                 Overrides HTTP_PROXY and HTTPS_PROXY.
  @B{NO_PROXY}       A comma-separated list of domains to not use proxies for.
  @B{SAFE_KNOWN_HOSTS_FILE}
                 The location of your known hosts file, used for
                 'ssh+socks5://' proxying. Uses '${HOME}/.ssh/known_hosts'
                 by default.
  @B{SAFE_SKIP_HOST_KEY_VALIDATION}
                 If set, 'ssh+socks5://' proxying will skip host key validation
                 validation of the remote ssh server.
  The proxy environment variables support proxies with the schemes 'http://',
  'https://', 'socks5://', or 'ssh+socks5://'. http, https, and socks5 do what they
  say - they'll proxy through the server with the hostname:port given using the
  protocol specified in the scheme.
  'ssh+socks5://' will open an SSH tunnel to the given server, then will start a
  local SOCKS5 proxy temporarily which sends its traffic through the SSH tunnel.
  Because this requires an SSH connection, some extra information is required.
  This type of proxy should be specified in the form
      ssh+socks5://<user>@<hostname>:<port>/<path-to-private-key>
  or  ssh+socks5://<user>@<hostname>:<port>?private-key=<path-to-private-key
  If no port is provided, port 22 is assumed.
  Encrypted private keys are not supported. Password authentication is also not
  supported.
  Your known_hosts file is used to verify the remote ssh server's host key. If no
  key for the given server is present, you will be prompted to add the key. If no
  TTY when no host key is present, safe will return with a failure.
`)
		return nil
	})
	r.Dispatch("list", &Help{
		Summary: "List secret keys",
		Usage:   "secret-helper set -p=[vault,google] --prefix=key_prefix",
		Description: `
		List all avalible secret keys found in google secret manager or hashicorp vault
		`,
		Type: NonDestructiveCommand,
	}, ListCmd)
	r.Dispatch("get", &Help{
		Summary: "Get single secret from key",
		Usage:   "secret-helper get -p=[vault,google] --prefix=key_prefix KEY",
		Description: `
		List all avalible secret keys found in google secret manager or hashicorp vault
		`,
		Type: NonDestructiveCommand,
	}, GetCmd)
	r.Dispatch("export", &Help{
		Summary: "Export variables in specific format ",
		Usage:   "secret-helper export -p=[vault,google] --prefix=key_prefix --output [bash|php|json]",
		Description: `
		Export variables found in google secret manager or hashicorp vault in specific format
		`,
		Type: NonDestructiveCommand,
	}, ExportCmd)
	r.Dispatch("set", &Help{
		Summary: "Set enviroment enviroment variables",
		Usage:   "secret-helper set -p=[vault,google] --prefix=key_prefix KEY",
		Description: `
		Set  all avalible secret keys/values found in google secret manager or hashicorp vault as enviroment variables
		`,
		Type: NonDestructiveCommand,
	}, SetCmd)
	env.Override(&opt)
	p, err := cli.NewParser(&opt, os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "@R{!! %s}\n", err)
		os.Exit(1)
	}

	if opt.Version {
		r.Execute("version")
		return
	}
	if opt.Help { //-h was given as a global arg
		r.Execute("help")
		return
	}

	for p.Next() {
		opt.SkipIfExists = !opt.Clobber

		if opt.Version {
			r.Execute("version")
			return
		}

		if p.Command == "" { //No recognized command was found
			r.Execute("help")
			return
		}

		if opt.Help { // -h or --help was given after a command
			r.Execute("help", p.Command)
			continue
		}

		os.Unsetenv("VAULT_SKIP_VERIFY")
		os.Unsetenv("SAFE_SKIP_VERIFY")
		if opt.Insecure {
			os.Setenv("VAULT_SKIP_VERIFY", "1")
			os.Setenv("SAFE_SKIP_VERIFY", "1")
		}

		//defer rc.Cleanup()
		err = r.Execute(p.Command, p.Args...)
		if err != nil {
			if strings.HasPrefix(err.Error(), "USAGE") {
				fmt.Fprintf(os.Stderr, "@Y{%s}\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "@R{!! %s}\n", err)
			}
			os.Exit(1)
		}
	}

	//If there were no args given, the above loop that would try to give help
	// doesn't execute at all, so we catch it here.
	if p.Command == "" {
		r.Execute("help")
	}

	if err = p.Error(); err != nil {
		fmt.Fprintf(os.Stderr, "@R{!! %s}\n", err)
		os.Exit(1)
	}
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

//Exits program with error if no Vault targeted
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
