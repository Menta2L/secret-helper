package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"

	"github.com/menta2l/secret-helper/prompt"
)

func LDAP(addr, path string) (string, error) {
	path = strings.Trim(path, "/")
	if path == "" {
		path = "ldap"
	}

	username := prompt.Normal("LDAP username: ")
	password := prompt.Secure("Password: ")

	body := struct {
		Password string `json:"password"`
	}{password}
	b, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", authurl(addr, "/v1/auth/%s/login/%s", path, username),
		strings.NewReader(string(b)))
	if err != nil {
		return "", err
	}

	if shouldDebug() {
		r, _ := httputil.DumpRequest(req, true)
		fmt.Fprintf(os.Stderr, "Request:\n%s\n----------------\n", r)
	}
	return authenticate(req)
}
