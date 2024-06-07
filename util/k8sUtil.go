/*
 * Copyright (c) 2024. Devtron Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package kube

//code copied from argocd

import (
	"golang.org/x/net/context"
	apiv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type KubeUtil struct {
	client      kubernetes.Interface
	labels      map[string]string
	annotations map[string]string
}

// updateFn will be called to set data for secret s. new will be true if the
// secret was created by the caller, or false if it has existed before.
type updateFn func(s *apiv1.Secret, new bool) error

// NewUtil returns a new kubeUtil receiver
func NewKubeUtil(client kubernetes.Interface) *KubeUtil {
	return &KubeUtil{client: client}
}

// CreateOrUpdateSecret creates or updates a secret, using the update function.
// If the secret is created, its labels and annotations are set if non-empty in
// the receiver. If the secret is updated, labels and annotations will not be
// touched.
func (ku *KubeUtil) CreateOrUpdateSecret(ns string, name string, update updateFn) error {
	var s *apiv1.Secret
	var err error
	var new bool

	s, err = ku.client.CoreV1().Secrets(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
		new = true
	}

	if new {
		s = &apiv1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Namespace:   ns,
				Labels:      ku.labels,
				Annotations: ku.annotations,
			},
		}
		s.Data = make(map[string][]byte)
	}

	err = update(s, new)
	if err != nil {
		return err
	}

	if new {
		_, err = ku.client.CoreV1().Secrets(ns).Create(context.Background(), s, metav1.CreateOptions{}) //(ku.ctx, s, metav1.CreateOptions{})
	} else {
		_, err = ku.client.CoreV1().Secrets(ns).Update(context.Background(), s, metav1.UpdateOptions{}) //(ku.ctx, s, metav1.UpdateOptions{})
	}

	return err

}

// CreateOrUpdateSecretField creates or updates a secret name in namespace ns, with given value for given field
func (ku *KubeUtil) CreateOrUpdateSecretField(ns string, name string, field string, value string) error {
	err := ku.CreateOrUpdateSecret(ns, name, func(s *apiv1.Secret, new bool) error {
		if s.Data == nil {
			s.Data = make(map[string][]byte)
		}
		s.Data[field] = []byte(value)
		return nil
	})
	return err
}

// CreateOrUpdateSecretData creates or updates a secret name in namespace ns, with given data.
// If merge is true, merges data with the existing data, otherwise overwrites it.
func (ku *KubeUtil) CreateOrUpdateSecretData(ns string, name string, data map[string][]byte, merge bool) error {
	err := ku.CreateOrUpdateSecret(ns, name, func(s *apiv1.Secret, new bool) error {
		if !merge || new {
			s.Data = data
		} else {
			for key, val := range data {
				s.Data[key] = val
			}
		}
		return nil
	})
	return err
}

// DeepCopy returns a copy of ku
func (ku *KubeUtil) DeepCopy() *KubeUtil {
	kun := &KubeUtil{
		client:      ku.client,
		labels:      ku.labels,
		annotations: ku.annotations,
	}
	return kun
}

// WithLabels returns a copy of ku with labels attached
func (ku *KubeUtil) WithLabels(labels map[string]string) *KubeUtil {
	kun := ku.DeepCopy()
	kun.labels = labels
	return kun
}

// WithAnnotations returns a copy of ku with annotations attached
func (ku *KubeUtil) WithAnnotations(annotations map[string]string) *KubeUtil {
	kun := ku.DeepCopy()
	kun.annotations = annotations
	return kun
}
