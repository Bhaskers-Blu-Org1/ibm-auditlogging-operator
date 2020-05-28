//
// Copyright 2020 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package resources

import (
	"fmt"

	operatorv1alpha1 "github.com/ibm/ibm-auditlogging-operator/pkg/apis/operator/v1alpha1"
	extv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/yaml"
)

const AuditPolicyCRDName = "auditpolicies.audit.policies.ibm.com"
const DefaultAuditPolicyName = "audit-policy-example"
const auditPolicyGroup = "audit.policies.ibm.com"
const auditPolicyKind = "AuditPolicy"
const auditPolicyVersion = "v1alpha1"

var defaultAuditPolicy = []byte(`
apiVersion: audit.policies.ibm.com/v1alpha1
kind: AuditPolicy # Verify if audit is enabled
metadata:
  name: audit-policy-example
  labels:
    category: "System-Integrity"
spec:
  namespaceSelector:
    include: []
    exclude: []
  clusterAuditPolicy:
    auditPolicyRules: {}
  remediationAction: inform # enforce or inform
`)

// FIX Cr is not being cleaned up
func BuildAuditPolicyCR() (*unstructured.Unstructured, error) {
	obj := &unstructured.Unstructured{}
	jsonSpec, err := yaml.YAMLToJSON(defaultAuditPolicy)
	if err != nil {
		return nil, fmt.Errorf("could not convert yaml to json: %v", err)
	}
	if err := obj.UnmarshalJSON(jsonSpec); err != nil {
		return nil, fmt.Errorf("could not unmarshal resource: %v", err)
	}
	obj.SetName(DefaultAuditPolicyName)
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   auditPolicyGroup,
		Kind:    auditPolicyKind,
		Version: auditPolicyVersion,
	})
	return obj, err
}

// BuildAuditPolicyCRD returns a CRD object
func BuildAuditPolicyCRD(instance *operatorv1alpha1.AuditLogging) *extv1beta1.CustomResourceDefinition {
	metaLabels := LabelsForMetadata(AuditPolicyControllerDeploy)
	metaLabels["controller-tools.k8s.io"] = "1.0"
	crd := &extv1beta1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:   AuditPolicyCRDName,
			Labels: metaLabels,
		},
		Spec: extv1beta1.CustomResourceDefinitionSpec{
			Group: auditPolicyGroup,
			Names: extv1beta1.CustomResourceDefinitionNames{
				Kind:       auditPolicyKind,
				Plural:     "auditpolicies",
				ShortNames: []string{"ap"},
			},
			Scope: "Namespaced",
			Validation: &extv1beta1.CustomResourceValidation{
				OpenAPIV3Schema: &extv1beta1.JSONSchemaProps{
					Properties: map[string]extv1beta1.JSONSchemaProps{
						"apiVersion": {
							Description: "APIVersion defines the versioned schema of this representation of an object. " +
								"Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. " +
								"More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#resources",
							Type: "string",
						},
						"kind": {
							Description: "'Kind is a string value representing the REST resource this object represents. " +
								"Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. " +
								"More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#types-kinds",
							Type: "string",
						},
						"metadata": {
							Type: "object",
						},
						"spec": {
							Properties: map[string]extv1beta1.JSONSchemaProps{
								"labelSelector": {
									Description: "selecting a list of namespaces where the policy applies",
									Type:        "object",
								},
								"namespaceSelector": {
									Description: "namespaces on which to run the policy",
									Properties: map[string]extv1beta1.JSONSchemaProps{
										"exclude": {
											Items: &extv1beta1.JSONSchemaPropsOrArray{
												Schema: &extv1beta1.JSONSchemaProps{
													Type: "string",
												},
											},
											Type: "array",
										},
										"include": {
											Items: &extv1beta1.JSONSchemaPropsOrArray{
												Schema: &extv1beta1.JSONSchemaProps{
													Type: "string",
												},
											},
											Type: "array",
										},
									},
									Type: "object",
								},
								"remediationAction": {
									Description: "remediate or enforce",
									Type:        "string",
								},
								"clusterAuditPolicy": {
									Description: "enforce, inform",
									Type:        "object",
								},
							},
							Type: "object",
						},
						"status": {
							Properties: map[string]extv1beta1.JSONSchemaProps{
								"auditDetails": {
									Description: "selecting a list of services to validate",
									Type:        "object",
								},
								"compliant": {
									Type: "string",
								},
							},
							Type: "object",
						},
					},
				},
			},
			Version: auditPolicyVersion,
		},
		Status: extv1beta1.CustomResourceDefinitionStatus{
			AcceptedNames: extv1beta1.CustomResourceDefinitionNames{
				Kind:   "",
				Plural: "",
			},
			Conditions:     []extv1beta1.CustomResourceDefinitionCondition{},
			StoredVersions: []string{},
		},
	}

	return crd
}
