package wrapper

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/oauth2/google"
	"k8s.io/client-go/tools/clientcmd"

	"code.cloudfoundry.org/cli/api/cloudcontroller"
)

type K8sAuth struct {
	connection cloudcontroller.Connection
}

func NewK8sAuth() *K8sAuth {
	return &K8sAuth{}
}

type ExecCredential struct {
	APIVersion string               `json:"apiVersion"`
	Kind       string               `json:"ExecCredential"`
	Status     ExecCredentialStatus `json:"status"`
}

type ExecCredentialStatus struct {
	Token string `json:"token"`
}

func (t *K8sAuth) Make(request *cloudcontroller.Request, passedResponse *cloudcontroller.Response) error {
	pathOpts := clientcmd.NewDefaultPathOptions()
	conf, err := pathOpts.GetStartingConfig()
	if err != nil {
		return err
	}

	curCtxName := conf.CurrentContext
	if curCtxName == "" {
		return fmt.Errorf("current context not set")
	}

	curCtx, ok := conf.Contexts[curCtxName]
	if !ok {
		return fmt.Errorf("current context not present in kube config")
	}

	user, ok := conf.AuthInfos[curCtx.AuthInfo]
	if !ok {
		return fmt.Errorf("current user not present in kube config")
	}

	if user.Exec != nil {
		cmd := exec.Command(user.Exec.Command)
		cmd.Args = append(cmd.Args, user.Exec.Args...)

		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		out, err := cmd.Output()
		if err != nil {
			return err
		}

		auth := "execcredential " + base64.StdEncoding.EncodeToString(out)
		request.Header.Set("Authorization", auth)
	}

	if user.AuthProvider != nil && user.AuthProvider.Name == "gcp" {
		tokenSource, err := google.DefaultTokenSource(context.Background(), "https://www.googleapis.com/auth/cloud-platform")
		if err != nil {
			return fmt.Errorf("could not get tokenSource: %w", err)
		}

		token, err := tokenSource.Token()
		if err != nil {
			return fmt.Errorf("could not get token: %w", err)
		}

		cred := ExecCredential{
			APIVersion: "client.authentication.k8s.io/v1beta1",
			Kind:       "ExecCredential",
			Status: ExecCredentialStatus{
				Token: token.AccessToken,
			},
		}
		credJson, _ := json.Marshal(cred)

		auth := "execcredential " + base64.StdEncoding.EncodeToString(credJson)
		request.Header.Set("Authorization", auth)
	}

	return t.connection.Make(request, passedResponse)
}

func (t *K8sAuth) Wrap(innerconnection cloudcontroller.Connection) cloudcontroller.Connection {
	t.connection = innerconnection
	return t
}
