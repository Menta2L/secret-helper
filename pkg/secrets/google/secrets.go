package google

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"github.com/menta2l/secret-helper/pkg/secrets"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

const oauth2scope = "https://www.googleapis.com/auth/cloud-platform"

// SecretsProvider Google Cloud secrets provider
type SecretsProvider struct {
	ctx         context.Context
	credentials *google.Credentials
	client      *secretmanager.Client
	clientError error
	project     string
}

func NewGoogleSecretsProvider(ctx context.Context) (secrets.Provider, error) {
	sp := SecretsProvider{}
	sp.ctx = ctx
	sp.credentials, sp.clientError = google.FindDefaultCredentials(sp.ctx, oauth2scope)
	if sp.clientError != nil {
		return nil, sp.clientError
	}
	if project, ok := os.LookupEnv("GOOGLE_CLOUD_PROJECT"); ok {
		sp.credentials.ProjectID = project
	}

	if sp.project != "" {
		sp.credentials.ProjectID = sp.project
	}

	if sp.credentials.ProjectID == "" {
		return nil, fmt.Errorf("no project specified and no default project set")
	}
	sp.project = sp.credentials.ProjectID
	sp.client, sp.clientError = secretmanager.NewClient(sp.ctx, option.WithCredentials(sp.credentials))
	if sp.clientError != nil {
		return nil, sp.clientError
	}
	return &sp, nil
}
func (sp SecretsProvider) ListSecrets(ctx context.Context, prefix string) ([]string, error) {
	var envs []string
	// Build the request.
	req := &secretmanagerpb.ListSecretsRequest{
		Parent: "projects/" + sp.project,
	}

	// Call the API.
	it := sp.client.ListSecrets(ctx, req)
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}

		if err != nil {
			return envs, fmt.Errorf("failed to list secret versions: %v", err)
		}
		path := resp.GetName()
		if match, _ := regexp.MatchString("projects/[^/]+/secrets/"+prefix+".*", path); match {
			parts := strings.Split(path, "/")
			envs = append(envs, parts[len(parts)-1])

		}
	}

	return envs, nil
}
func (sp SecretsProvider) GetSecret(ctx context.Context, preffix string, key string) (string, error) {
	path := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", sp.project, key)

	accessRequest := &secretmanagerpb.AccessSecretVersionRequest{
		Name: path,
	}
	result, err := sp.client.AccessSecretVersion(sp.ctx, accessRequest)
	if err != nil {
		return "", err
	}

	return string(result.Payload.Data), nil

}
func (sp SecretsProvider) GetSecrets(ctx context.Context, preffix string) ([]string, error) {
	var envs []string
	return envs, nil
}
