package wrapper

import (
	"fmt"
	"net/http"

	"code.cloudfoundry.org/cli/actor/v7action"
	"code.cloudfoundry.org/cli/api/cloudcontroller"
	"code.cloudfoundry.org/cli/command"
	"k8s.io/client-go/transport"

	_ "k8s.io/client-go/plugin/pkg/client/auth/azure"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
)

type KubernetesAuthentication struct {
	connection      cloudcontroller.Connection
	config          command.Config
	k8sConfigGetter v7action.KubernetesConfigGetter
}

func NewKubernetesAuthentication(
	config command.Config,
	k8sConfigGetter v7action.KubernetesConfigGetter,
) *KubernetesAuthentication {

	return &KubernetesAuthentication{
		config:          config,
		k8sConfigGetter: k8sConfigGetter,
	}
}

func (a *KubernetesAuthentication) Make(request *cloudcontroller.Request, passedResponse *cloudcontroller.Response) error {
	restConfig, authIsSet, err := command.SetKubernetesAuthenticationHeaders(request.Header, a.config, a.k8sConfigGetter)
	if err != nil {
		return err
	}
	if authIsSet {
		return a.connection.Make(request, passedResponse)
	}

	transportConfig, err := restConfig.TransportConfig()
	if err != nil {
		return fmt.Errorf("failed to get transport config: %w", err)
	}

	var roundtripper http.RoundTripper
	if transportConfig.WrapTransport == nil {
		// i.e. not auth-provider or exec plugin
		roundtripper, err = transport.HTTPWrappersForConfig(transportConfig, connectionRoundTripper{
			connection: a.connection,
			ccRequest:  request,
			ccResponse: passedResponse,
		})
		if err != nil {
			return fmt.Errorf("failed to create new transport: %w", err)
		}
	} else {
		roundtripper = transportConfig.WrapTransport(connectionRoundTripper{
			connection: a.connection,
			ccRequest:  request,
			ccResponse: passedResponse,
		})
	}

	_, err = roundtripper.RoundTrip(request.Request)

	return err
}

func (a *KubernetesAuthentication) Wrap(innerconnection cloudcontroller.Connection) cloudcontroller.Connection {
	a.connection = innerconnection

	return a
}

type connectionRoundTripper struct {
	connection cloudcontroller.Connection
	ccRequest  *cloudcontroller.Request
	ccResponse *cloudcontroller.Response
}

func (rt connectionRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// The passed `*req` is a shallow clone of the original `*req` with the auth header added.
	// So we need to reset it on the `ccRequest`.
	rt.ccRequest.Request = req

	err := rt.connection.Make(rt.ccRequest, rt.ccResponse)
	if err != nil {
		return nil, err
	}

	return rt.ccResponse.HTTPResponse, nil
}
