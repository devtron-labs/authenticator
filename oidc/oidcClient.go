package oidc

import (
	"net"
	"net/http"
	"net/url"
	"path"
	"time"
)

func GetOidcClient(dexServerAddress string, settings *Settings) (*ClientApp, func(writer http.ResponseWriter, request *http.Request), error) {
	dexClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: nil,
			Proxy:           http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
	dexProxy := NewDexHTTPReverseProxy(dexServerAddress, dexClient.Transport)
	cahecStore := &Cache{OidcState: map[string]*OIDCState{}}
	oidcClient, err := NewClientApp(settings, cahecStore, "/")
	if err != nil {
		return nil, nil, err
	}
	return oidcClient, dexProxy, err
}

const DexProxyUri = "api/dex"

type DexConfig struct {
	DexServerAddress string `env:"dexServerAddress" envDefault:"http://argocd-dex-server.devtroncd:5556/authenticator"`
	Url              string `env:"authenticatorUrl" envDefault:"https://demo.devtron.info:32443/authenticator/"`
	DexClientSecret  string `env:"dexClientSecret" envDefault:""`
	DexCLIClientID   string `env:"dexCLIClientID" envDefault:"argo-cd"`
	ServeTls         bool   `env:"serveTls" envDefault:"false"`
}

func (c *DexConfig) getDexProxyUrl() (string, error) {
	u, err := url.Parse(c.Url)
	if err != nil {
		return "", err
	}
	u.Path = path.Join(u.Path, DexProxyUri)
	s := u.String()
	return s, nil
}
