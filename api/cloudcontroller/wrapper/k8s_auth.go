package wrapper

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"code.cloudfoundry.org/cli/api/cloudcontroller"

	_ "k8s.io/client-go/plugin/pkg/client/auth/azure"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
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

	if user.AuthProvider != nil {
		cluster := conf.Clusters[curCtx.Cluster].Server
		persister := clientcmd.PersisterForUser(pathOpts, curCtx.AuthInfo)
		authProvider, err := rest.GetAuthProvider(cluster, user.AuthProvider, persister)
		if err != nil {
			return fmt.Errorf("could not get auth provider: %w", err)
		}

		connectionRoundTripper := ConnectionRoundTripper{connection: t.connection, response: passedResponse}
		wrappedRoundTripper := authProvider.WrapTransport(connectionRoundTripper)
		_, err = wrappedRoundTripper.RoundTrip(request.Request)
		return err
	}

	return t.connection.Make(request, passedResponse)
}

func (t *K8sAuth) Wrap(innerconnection cloudcontroller.Connection) cloudcontroller.Connection {
	t.connection = innerconnection
	return t
}

type ConnectionRoundTripper struct {
	connection cloudcontroller.Connection
	response   *cloudcontroller.Response
}

func (rt ConnectionRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var bodyBytes []byte
	var err error

	if req.Body != nil {
		bodyBytes, err = ioutil.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
	}

	ccReq := cloudcontroller.NewRequest(req, bytes.NewReader(bodyBytes))
	err = rt.connection.Make(ccReq, rt.response)
	if err != nil {
		return nil, err
	}

	return rt.response.HTTPResponse, nil
}
