package wrapper

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"

	"k8s.io/client-go/pkg/apis/clientauthentication"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/transport"

	"code.cloudfoundry.org/cli/api/cloudcontroller"
	"code.cloudfoundry.org/cli/command"

	_ "k8s.io/client-go/plugin/pkg/client/auth/azure"
	authexec "k8s.io/client-go/plugin/pkg/client/auth/exec"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

type K8sAuth struct {
	connection cloudcontroller.Connection
	config     command.Config
}

func NewK8sAuth(config command.Config) *K8sAuth {
	return &K8sAuth{
		config: config,
	}
}

func (t *K8sAuth) Make(request *cloudcontroller.Request, passedResponse *cloudcontroller.Response) error {
	pathOpts := clientcmd.NewDefaultPathOptions()
	conf, err := pathOpts.GetStartingConfig()
	if err != nil {
		return err
	}

	k8sUser := t.config.KubernetesUser()
	if k8sUser == "" {
		// not logged in yet
		return nil
	}

	if authInfo, ok := conf.AuthInfos[t.config.KubernetesUser()]; ok && authInfo.Token != "" {
		return t.performUserTokenAuthentication(conf, request, passedResponse)
	}

	if _, ok := conf.Contexts[t.config.KubernetesUser()]; ok {
		return t.performContextAuthentication(pathOpts, conf, request, passedResponse)
	}

	return fmt.Errorf("don't how to authenticate %q", t.config.KubernetesUser())
}

func (t *K8sAuth) performContextAuthentication(k8sConfigPathOptions *clientcmd.PathOptions, k8sConfig *clientcmdapi.Config, request *cloudcontroller.Request, passedResponse *cloudcontroller.Response) error {
	userCtx := k8sConfig.Contexts[t.config.KubernetesUser()]
	user, ok := k8sConfig.AuthInfos[userCtx.AuthInfo]
	if !ok {
		return fmt.Errorf("auth info %q not present for user %q in kube config", userCtx.AuthInfo, t.config.KubernetesUser())
	}

	if user.Exec != nil {
		authProvider, err := authexec.GetAuthenticator(user.Exec)
		if err != nil {
			return fmt.Errorf("could not get auth provider: %w", err)
		}

		var transportCfg transport.Config
		authProvider.UpdateTransportConfig(&transportCfg)

		cert, err := transportCfg.TLS.GetCert()
		if err != nil {
			return fmt.Errorf("could not get creds from exec plugin: %w", err)
		}

		if cert != nil {
			var buf bytes.Buffer

			if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Leaf.Raw}); err != nil {
				return fmt.Errorf("could not convert certificate to PEM format: %w", err)
			}
			certPEM := buf.String()

			key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
			if err != nil {
				return fmt.Errorf("could not marshal private key: %w", err)
			}

			buf.Reset()
			if err := pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: key}); err != nil {
				return fmt.Errorf("could not convert key to PEM format: %w", err)
			}
			keyPEM := buf.String()

			execCredBytes, err := json.Marshal(clientauthentication.ExecCredential{
				Status: &clientauthentication.ExecCredentialStatus{
					ClientCertificateData: certPEM,
					ClientKeyData:         keyPEM,
				},
			})
			if err != nil {
				return fmt.Errorf("could not marshal execCred to json: %w", err)
			}

			auth := "execcredential " + base64.StdEncoding.EncodeToString(execCredBytes)
			request.Header.Set("Authorization", auth)
		}

		connectionRoundTripper := ConnectionRoundTripper{connection: t.connection, response: passedResponse}
		wrappedRoundTripper := transportCfg.WrapTransport(connectionRoundTripper)
		_, err = wrappedRoundTripper.RoundTrip(request.Request)
		return err
	}

	if user.AuthProvider != nil {
		cluster := k8sConfig.Clusters[userCtx.Cluster].Server
		persister := clientcmd.PersisterForUser(k8sConfigPathOptions, userCtx.AuthInfo)
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

func (t *K8sAuth) performUserTokenAuthentication(k8sConfig *clientcmdapi.Config, request *cloudcontroller.Request, passedResponse *cloudcontroller.Response) error {
	authInfo := k8sConfig.AuthInfos[t.config.KubernetesUser()]
	auth := "Bearer " + authInfo.Token
	request.Header.Set("Authorization", auth)

	connectionRoundTripper := ConnectionRoundTripper{connection: t.connection, response: passedResponse}
	_, err := connectionRoundTripper.RoundTrip(request.Request)
	return err
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
