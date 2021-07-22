package auth

import (
	"github.com/menta2l/secret-helper/prompt"
)

func Token(addr string) (string, error) {
	return prompt.Secure("Token: "), nil
}
