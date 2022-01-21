/*
 * Copyright (c) 2021 Devtron Labs
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package client

import (
	"flag"
	"fmt"
	"github.com/caarlos0/env/v6"
	"gopkg.in/yaml.v3"
	v1 "k8s.io/api/core/v1"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"os/user"
	"path/filepath"
	"time"
)

type LocalDevMode bool

type K8sClient struct {
	runtimeConfig *RuntimeConfig
	config        *rest.Config
}

type RuntimeConfig struct {
	LocalDevMode LocalDevMode `env:"RUNTIME_CONFIG_LOCAL_DEV" envDefault:"false"`
}

func GetRuntimeConfig() (*RuntimeConfig, error) {
	cfg := &RuntimeConfig{}
	err := env.Parse(cfg)
	return cfg, err
}

func NewK8sClient(runtimeConfig *RuntimeConfig) (*K8sClient, error) {
	config, err := getKubeConfig(runtimeConfig.LocalDevMode)
	if err != nil {
		return nil, err
	}
	return &K8sClient{
		runtimeConfig: runtimeConfig,
		config:        config,
	}, nil
}

//TODO use it as generic function across system
func getKubeConfig(devMode LocalDevMode) (*rest.Config, error) {
	if devMode {
		usr, err := user.Current()
		if err != nil {
			return nil, err
		}
		kubeconfig := flag.String("kubeconfig-authenticator", filepath.Join(usr.HomeDir, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
		flag.Parse()
		restConfig, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
		if err != nil {
			return nil, err
		}
		return restConfig, nil
	} else {
		restConfig, err := rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
		return restConfig, nil
	}
}

func (impl *K8sClient) GetArgoConfig() (secret *v1.Secret, cm *v1.ConfigMap, err error) {
	clientSet, err := kubernetes.NewForConfig(impl.config)
	if err != nil {
		return nil, nil, err
	}
	secret, err = clientSet.CoreV1().Secrets(ArgocdNamespaceName).Get(ArgoCDSecretName, v12.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	cm, err = clientSet.CoreV1().ConfigMaps(ArgocdNamespaceName).Get(ArgoCDConfigMapName, v12.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	return secret, cm, nil
}

// argocd specific conf
const (
	SettingAdminPasswordHashKey = "admin.password"
	// SettingAdminPasswordMtimeKey designates the key for a root password mtime inside a Kubernetes secret.
	SettingAdminPasswordMtimeKey = "admin.passwordMtime"
	SettingAdminEnabledKey       = "admin.enabled"
	SettingAdminTokensKey        = "admin.tokens"

	SettingServerSignatureKey = "server.secretkey"
	settingURLKey             = "url"
	ArgoCDConfigMapName       = "argocd-cm"
	ArgoCDSecretName          = "argocd-secret"
	ArgocdNamespaceName       = "devtroncd"
	CallbackEndpoint          = "/auth/callback"
	settingDexConfigKey       = "dex.config"
	DexCallbackEndpoint       = "/api/dex/callback"
	initialPasswordLength     = 16
	initialPasswordSecretName = "devtron-secret"
)

func (impl *K8sClient) GetServerSettings() (*DexConfig, error) {
	cfg := &DexConfig{}
	secret, cm, err := impl.GetArgoConfig()
	if err != nil {
		return nil, err
	}
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}
	if settingServerSignatur, ok := secret.Data[SettingServerSignatureKey]; ok {
		cfg.ServerSecret = string(settingServerSignatur)
	}
	if settingURL, ok := cm.Data[settingURLKey]; ok {
		cfg.Url = settingURL
	}
	if adminPasswordMtimeBytes, ok := secret.Data[SettingAdminPasswordMtimeKey]; ok {
		if mTime, err := time.Parse(time.RFC3339, string(adminPasswordMtimeBytes)); err == nil {
			cfg.AdminPasswordMtime = mTime
		}
	}
	cfg.DexConfigRaw = cm.Data[settingDexConfigKey]
	return cfg, nil
}

func (impl *K8sClient) GenerateDexConfigYAML(settings *DexConfig) ([]byte, error) {
	redirectURL, err := settings.RedirectURL()
	if err != nil {
		return nil, fmt.Errorf("failed to infer redirect url from config: %v", err)
	}
	var dexCfg map[string]interface{}
	if len(settings.DexConfigRaw) > 0 {
		err = yaml.Unmarshal([]byte(settings.DexConfigRaw), &dexCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal dex.config from configmap: %v", err)
		}
	}
	issuer, err := settings.getDexProxyUrl()
	if err != nil {
		return nil, fmt.Errorf("failed to find issuer url: %v", err)
	}
	dexCfg["issuer"] = issuer
	dexCfg["storage"] = map[string]interface{}{
		"type": "memory",
	}
	dexCfg["web"] = map[string]interface{}{
		"http": "0.0.0.0:5556",
	}
	dexCfg["grpc"] = map[string]interface{}{
		"addr": "0.0.0.0:5557",
	}
	dexCfg["telemetry"] = map[string]interface{}{
		"http": "0.0.0.0:5558",
	}
	dexCfg["oauth2"] = map[string]interface{}{
		"skipApprovalScreen": true,
	}

	argoCDStaticClient := map[string]interface{}{
		"id":     settings.DexClientID,
		"name":   "devtron",
		"secret": settings.DexOAuth2ClientSecret(),
		"redirectURIs": []string{
			redirectURL,
		},
	}

	staticClients, ok := dexCfg["staticClients"].([]interface{})
	if ok {
		dexCfg["staticClients"] = append([]interface{}{argoCDStaticClient}, staticClients...)
	} else {
		dexCfg["staticClients"] = []interface{}{argoCDStaticClient}
	}

	dexRedirectURL, err := settings.DexRedirectURL()
	if err != nil {
		return nil, err
	}
	connectors, ok := dexCfg["connectors"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("malformed Dex configuration found")
	}
	for i, connectorIf := range connectors {
		connector, ok := connectorIf.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("malformed Dex configuration found")
		}
		connectorType := connector["type"].(string)
		if !needsRedirectURI(connectorType) {
			continue
		}
		connectorCfg, ok := connector["config"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("malformed Dex configuration found")
		}
		connectorCfg["redirectURI"] = dexRedirectURL
		connector["config"] = connectorCfg
		connectors[i] = connector
	}
	dexCfg["connectors"] = connectors
	return yaml.Marshal(dexCfg)
}

// needsRedirectURI returns whether or not the given connector type needs a redirectURI
// Update this list as necessary, as new connectors are added
// https://github.com/dexidp/dex/tree/master/Documentation/connectors
func needsRedirectURI(connectorType string) bool {
	switch connectorType {
	case "oidc", "saml", "microsoft", "linkedin", "gitlab", "github", "bitbucket-cloud", "openshift":
		return true
	}
	return false
}
