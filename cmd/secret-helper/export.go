package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/menta2l/secret-helper/pkg/secrets/google"
	"github.com/menta2l/secret-helper/pkg/secrets/vault"
)

var bashTpl string = `{{range $Name, $Value := . -}}export {{$Name}}={{$Value}}{{end}}
`
var phpTpl string = `<?php
{{range $Name, $Value := . -}}
define('{{$Name}}', '{{$Value}}');
{{end}}
`

func ExportCmd(command string, args ...string) error {

	if opt.Export.Provider == "" {
		return fmt.Errorf("please specify --provider=[vault|google]")
	}
	if opt.Export.Output == "" {
		return fmt.Errorf("please specify --output=[bash|php|json]")
	}
	var env map[string]interface{}
	env = make(map[string]interface{})
	switch opt.Export.Provider {
	case "google":
		p, err := google.NewGoogleSecretsProvider(context.Background())
		if err != nil {
			return err
		}
		keys, err := p.ListSecrets(context.Background(), opt.Export.Prefix)
		if err != nil {
			return err
		}

		for _, k := range keys {
			val, err := p.GetSecret(context.Background(), opt.Export.Prefix, k)
			if err != nil {
				return err
			}
			env[strings.ToUpper(k)] = val

		}
	case "vault":
		p, err := vault.NewVaultSecretsProvider(context.Background())
		if err != nil {
			return err
		}
		keys, err := p.ListSecrets(context.Background(), opt.Export.Prefix)
		if err != nil {
			return err
		}

		for _, k := range keys {
			val, err := p.GetSecret(context.Background(), opt.Export.Prefix, k)
			if err != nil {
				return err
			}
			env[strings.ToUpper(k)] = val

		}
	default:
		return fmt.Errorf("unsupported provider %s", opt.Get.Provider)
	}
	return exportOutput(env)
}
func exportOutput(data map[string]interface{}) error {
	switch opt.Export.Output {
	case "bash":
		templ, err := template.New("app").Parse(bashTpl)
		if err != nil {
			return err
		}
		err = templ.Execute(os.Stdout, data)
		if err != nil {
			return err
		}
	case "php":
		templ, err := template.New("app").Parse(phpTpl)
		if err != nil {
			return err
		}
		err = templ.Execute(os.Stdout, data)
		if err != nil {
			return err
		}
	case "json":
		prettyJSON, err := json.MarshalIndent(data, "", "    ")
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", string(prettyJSON))
	}
	return nil
}
