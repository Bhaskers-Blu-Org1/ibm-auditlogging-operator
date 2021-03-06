// +build !ignore_autogenerated

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

// Code generated by operator-sdk. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AuditLogging) DeepCopyInto(out *AuditLogging) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuditLogging.
func (in *AuditLogging) DeepCopy() *AuditLogging {
	if in == nil {
		return nil
	}
	out := new(AuditLogging)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AuditLogging) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AuditLoggingList) DeepCopyInto(out *AuditLoggingList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]AuditLogging, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuditLoggingList.
func (in *AuditLoggingList) DeepCopy() *AuditLoggingList {
	if in == nil {
		return nil
	}
	out := new(AuditLoggingList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AuditLoggingList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AuditLoggingSpec) DeepCopyInto(out *AuditLoggingSpec) {
	*out = *in
	out.Fluentd = in.Fluentd
	out.PolicyController = in.PolicyController
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuditLoggingSpec.
func (in *AuditLoggingSpec) DeepCopy() *AuditLoggingSpec {
	if in == nil {
		return nil
	}
	out := new(AuditLoggingSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AuditLoggingSpecFluentd) DeepCopyInto(out *AuditLoggingSpecFluentd) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuditLoggingSpecFluentd.
func (in *AuditLoggingSpecFluentd) DeepCopy() *AuditLoggingSpecFluentd {
	if in == nil {
		return nil
	}
	out := new(AuditLoggingSpecFluentd)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AuditLoggingSpecPolicyController) DeepCopyInto(out *AuditLoggingSpecPolicyController) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuditLoggingSpecPolicyController.
func (in *AuditLoggingSpecPolicyController) DeepCopy() *AuditLoggingSpecPolicyController {
	if in == nil {
		return nil
	}
	out := new(AuditLoggingSpecPolicyController)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AuditLoggingStatus) DeepCopyInto(out *AuditLoggingStatus) {
	*out = *in
	if in.Nodes != nil {
		in, out := &in.Nodes, &out.Nodes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuditLoggingStatus.
func (in *AuditLoggingStatus) DeepCopy() *AuditLoggingStatus {
	if in == nil {
		return nil
	}
	out := new(AuditLoggingStatus)
	in.DeepCopyInto(out)
	return out
}
