package cloudcontroller

import (
	"crypto/x509"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"code.cloudfoundry.org/cli/api/cloudcontroller/ccerror"
	"code.cloudfoundry.org/cli/util"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

// Config is for configuring a CloudControllerConnection.
type Config struct {
	DialTimeout       time.Duration
	SkipSSLValidation bool
}

// CloudControllerConnection represents a connection to the Cloud Controller
// server.
type CloudControllerConnection struct {
	HTTPClient *http.Client
	UserAgent  string
}

func NewConnection(config Config) *CloudControllerConnection {
	tr := &http.Transport{
		TLSClientConfig: util.NewTLSConfig(nil, config.SkipSSLValidation),
		Proxy:           http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			KeepAlive: 30 * time.Second,
			Timeout:   config.DialTimeout,
		}).DialContext,
	}

	return &CloudControllerConnection{
		HTTPClient: &http.Client{Transport: tr},
	}
}

// NewConnection returns a new CloudControllerConnection with provided
// configuration.
func NewK8sConnection(config Config, authInfo string) *CloudControllerConnection {
	pathOpts := clientcmd.NewDefaultPathOptions()
	k8sConfig, err := pathOpts.GetStartingConfig()
	if err != nil {
		panic(err)
	}

	restConfig, err := clientcmd.NewDefaultClientConfig(
		*k8sConfig,
		&clientcmd.ConfigOverrides{
			Context: api.Context{AuthInfo: authInfo},
		}).ClientConfig()
	if err != nil {
		panic(err)
	}

	restConfig.Insecure = config.SkipSSLValidation
	restConfig.Timeout = config.DialTimeout
	restConfig.CAData = nil
	restConfig.CAFile = ""

	transport, err := rest.TransportFor(restConfig)
	if err != nil {
		panic(err)
	}

	return &CloudControllerConnection{
		HTTPClient: &http.Client{Transport: transport},
	}
}

// Make performs the request and parses the response.
func (connection *CloudControllerConnection) Make(request *Request, passedResponse *Response) error {
	// In case this function is called from a retry, passedResponse may already
	// be populated with a previous response. We reset in case there's an HTTP
	// error and we don't repopulate it in populateResponse.
	passedResponse.reset()

	response, err := connection.HTTPClient.Do(request.Request)
	if err != nil {
		return connection.processRequestErrors(request.Request, err)
	}

	return connection.populateResponse(response, passedResponse)
}

func (*CloudControllerConnection) handleStatusCodes(response *http.Response, passedResponse *Response) error {
	if response.StatusCode == http.StatusNoContent {
		passedResponse.RawResponse = []byte("{}")
	} else {
		rawBytes, err := ioutil.ReadAll(response.Body)
		defer response.Body.Close()
		if err != nil {
			return err
		}

		passedResponse.RawResponse = rawBytes
	}

	if response.StatusCode >= 400 {
		return ccerror.RawHTTPStatusError{
			StatusCode:  response.StatusCode,
			RawResponse: passedResponse.RawResponse,
			RequestIDs:  response.Header["X-Vcap-Request-Id"],
		}
	}

	return nil
}

// handleWarnings looks for the "X-Cf-Warnings" header in the cloud controller
// response and URI decodes them. The value can contain multiple warnings that
// are comma separated.
func (*CloudControllerConnection) handleWarnings(response *http.Response) ([]string, error) {
	rawWarnings := response.Header["X-Cf-Warnings"]

	var warnings []string
	for _, rawWarningsCommaSeparated := range rawWarnings {
		for _, rawWarning := range strings.Split(rawWarningsCommaSeparated, ",") {
			warning, err := url.QueryUnescape(rawWarning)
			if err != nil {
				return nil, err
			}
			warnings = append(warnings, strings.Trim(warning, " "))
		}
	}

	return warnings, nil
}

func (connection *CloudControllerConnection) populateResponse(response *http.Response, passedResponse *Response) error {
	passedResponse.HTTPResponse = response

	warnings, err := connection.handleWarnings(response)
	if err != nil {
		return err
	}
	passedResponse.Warnings = warnings

	if resourceLocationURL := response.Header.Get("Location"); resourceLocationURL != "" {
		passedResponse.ResourceLocationURL = resourceLocationURL
	}

	err = connection.handleStatusCodes(response, passedResponse)
	if err != nil {
		return err
	}

	if passedResponse.DecodeJSONResponseInto != nil {
		err = DecodeJSON(passedResponse.RawResponse, passedResponse.DecodeJSONResponseInto)
		if err != nil {
			return err
		}
	}

	return nil
}

func (*CloudControllerConnection) processRequestErrors(request *http.Request, err error) error {
	switch e := err.(type) {
	case *url.Error:
		switch urlErr := e.Err.(type) {
		case x509.UnknownAuthorityError:
			return ccerror.UnverifiedServerError{
				URL: request.URL.String(),
			}
		case x509.HostnameError:
			return ccerror.SSLValidationHostnameError{
				Message: urlErr.Error(),
			}
		default:
			return ccerror.RequestError{Err: e}
		}
	default:
		return err
	}
}
