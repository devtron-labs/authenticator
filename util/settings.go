package kube

import (
	"crypto/rand"
	"fmt"
	"github.com/devtron-labs/authenticator/client"
	passwordutil "github.com/devtron-labs/authenticator/password"
	v1 "k8s.io/api/core/v1"
	"math/big"
	"time"
)

const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"

func InitialiseSettings(k8sClient *client.K8sClient) error {
	restClient, err := k8sClient.GetRestClient()
	if err != nil {
		return err
	}
	kubeutil := NewKubeUtil(restClient)
	secret, _, err := k8sClient.GetDevtronConfig()
	if err != nil {
		return err
	}
	var hashedPassword string
	newPassword := false
	if _, ok := secret.Data[client.SettingAdminPasswordHashKey]; !ok {
		randBytes := make([]byte, client.InitialPasswordLength)
		for i := 0; i < client.InitialPasswordLength; i++ {
			num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
			if err != nil {
				return err
			}
			randBytes[i] = letters[num.Int64()]
		}
		initialPassword := string(randBytes)
		hashedPassword, err = passwordutil.HashPassword(initialPassword)
		err = kubeutil.CreateOrUpdateSecretField(client.DevtronDefaultNamespaceName, client.DevtronSecretName, client.ADMIN_PASSWORD, initialPassword)
		if err != nil {
			return err
		}
		newPassword = true
	}
	passwordTime := time.Now()
	err = kubeutil.CreateOrUpdateSecret(client.DevtronDefaultNamespaceName, client.DevtronSecretName, func(s *v1.Secret, new bool) error {
		if s.Data == nil {
			s.Data = make(map[string][]byte)
		}
		if newPassword {
			s.Data[client.SettingAdminPasswordHashKey] = []byte(hashedPassword)
			s.Data[client.SettingAdminPasswordMtimeKey] = []byte(passwordTime.Format(time.RFC3339))
		}
		signature := s.Data[client.SettingServerSignatureKey]
		if len(signature) == 0 {
			signature, err := MakeSignature(32)
			if err != nil {
				return err
			}
			s.Data[client.SettingServerSignatureKey] = signature
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func MigrateDexConfigFromAcdToDevtronSecret(k8sClient *client.K8sClient) (bool, error) {
	restClient, err := k8sClient.GetRestClient()
	if err != nil {
		return false, err
	}
	kubeutil := NewKubeUtil(restClient)
	devtronSecret, _, err := k8sClient.GetDevtronConfig()
	if err != nil {
		return false, err
	}
	acdSecret, acdConfigMap, err := k8sClient.GetArgocdConfig()
	if err != nil {
		return false, err
	}
	operationSuccess := false
	retryCount := 0
	updateRequired := false
	for !operationSuccess && retryCount < 3 {
		retryCount = retryCount + 1
		if acdConfigMap.Data == nil && acdSecret.Data == nil {
			// do nothing if there is no config available on acd config
			break
		}
		if acdConfigMap.Data[client.SettingDexConfigKey] == "" || acdConfigMap.Data[client.SettingURLKey] == "" {
			// do nothing if there is no dex config or url present on acd config
			break
		}
		if acdSecret.Data[client.SettingAdminPasswordHashKey] == nil || acdSecret.Data[client.SettingAdminPasswordMtimeKey] == nil ||
			acdSecret.Data[client.SettingServerSignatureKey] == nil {
			// do nothing if there is no dex related config present on acd secret
			break
		}
		if devtronSecret.Data == nil {
			data := make(map[string][]byte)
			devtronSecret.Data = data
		}
		if _, ok := devtronSecret.Data[client.SettingDexConfigKey]; !ok {
			devtronSecret.Data[client.SettingDexConfigKey] = []byte(acdConfigMap.Data[client.SettingDexConfigKey])
			updateRequired = true
		}
		if _, ok := devtronSecret.Data[client.SettingURLKey]; !ok {
			devtronSecret.Data[client.SettingURLKey] = []byte(acdConfigMap.Data[client.SettingURLKey])
			updateRequired = true
		}
		if _, ok := devtronSecret.Data[client.SettingAdminPasswordHashKey]; !ok {
			devtronSecret.Data[client.SettingAdminPasswordHashKey] = acdSecret.Data[client.SettingAdminPasswordHashKey]
			updateRequired = true
		}
		if _, ok := devtronSecret.Data[client.SettingAdminPasswordMtimeKey]; !ok {
			devtronSecret.Data[client.SettingAdminPasswordMtimeKey] = acdSecret.Data[client.SettingAdminPasswordMtimeKey]
			updateRequired = true
		}
		if _, ok := devtronSecret.Data[client.SettingServerSignatureKey]; !ok {
			devtronSecret.Data[client.SettingServerSignatureKey] = acdSecret.Data[client.SettingServerSignatureKey]
			updateRequired = true
		}
		if _, ok := devtronSecret.Data[client.ADMIN_PASSWORD]; !ok {
			devtronSecret.Data[client.ADMIN_PASSWORD] = devtronSecret.Data[client.SettingAdminAcdPasswordKey]
			updateRequired = true
		}

		// here create or update devtron secret and migrate and store config for dex
		if updateRequired {
			err = kubeutil.CreateOrUpdateSecret(client.DevtronDefaultNamespaceName, client.DevtronSecretName, func(s *v1.Secret, new bool) error {
				if s.Data == nil {
					s.Data = make(map[string][]byte)
				}
				s.Data = devtronSecret.Data
				return nil
			})
		}
		operationSuccess = true
	}
	if updateRequired && !operationSuccess {
		return false, fmt.Errorf("unable to update devtron secret")
	}
	return true, nil
}
