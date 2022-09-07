package kube

import (
	"crypto/rand"
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
		err = kubeutil.CreateOrUpdateSecretField(client.DevtronDefaultNamespaceName, client.DevtronSecretName, client.SettingAdminPasswordHashKey, initialPassword)
		if err != nil {
			return err
		}
		newPassword = true
	}
	passwordTime := time.Now()
	err = kubeutil.CreateOrUpdateSecret(client.DevtronDefaultNamespaceName, client.DevtronConfigMapName, func(s *v1.Secret, new bool) error {
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
