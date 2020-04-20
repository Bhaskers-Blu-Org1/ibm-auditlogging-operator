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
	"reflect"
	"strconv"
	"strings"

	operatorv1alpha1 "github.com/ibm/ibm-auditlogging-operator/pkg/apis/operator/v1alpha1"
	yaml "gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var fluentdMainConfigData = `
fluent.conf: |-
    # Input plugins (Supports Systemd and HTTP)
    @include /fluentd/etc/source.conf

    # Output plugins (Only use one output plugin conf file at a time.)
`
var qradarPlugin = `@include /fluentd/etc/remoteSyslog.conf`
var splunkPlugin = `@include /fluentd/etc/splunkHEC.conf`

var sourceConfigData1 = `
source.conf: |-
    <source>
        @type systemd
        @id input_systemd_icp
        @log_level info
        tag icp-audit
        path `
var sourceConfigData2 = `
        matches '[{ "SYSLOG_IDENTIFIER": "icp-audit" }]'
        read_from_head true
        <storage>
          @type local
          persistent true
          path /icp-audit
        </storage>
        <entry>
          fields_strip_underscores true
          fields_lowercase true
        </entry>
    </source>`
var sourceConfigData3 = `
    <source>
        @type http
        # Tag is not supported in yaml, must be set by request path (/icp-audit.http is required for validation and export)
        port `
var sourceConfigData4 = `
        bind 0.0.0.0
        body_size_limit 32m
        keepalive_timeout 10s
        <transport tls>
          ca_path /fluentd/etc/https/ca.crt
          cert_path /fluentd/etc/https/tls.crt
          private_key_path /fluentd/etc/https/tls.key
        </transport>
        <parse>
          @type json
        </parse>
    </source>
    <filter icp-audit>
        @type parser
        format json
        key_name message
        reserve_data true
    </filter>`

var splunkConfigData = `
splunkHEC.conf: |-
    <match icp-audit icp-audit.**>
        @type splunk_hec
`

var splunkConfigData2 = `
        ca_file /fluentd/etc/tls/splunkCA.pem
        source ${tag}
    </match>`

var qRadarConfigData = `
remoteSyslog.conf: |-
    <match icp-audit icp-audit.**>
        @type copy
        <store>
            @type remote_syslog
`

var qRadarConfigData2 = `
            protocol tcp
            tls true
            ca_file /fluentd/etc/tls/qradar.crt
            packet_size 4096
            program fluentd
            <format>
                @type single_value
                message_key message
            </format>
        </store>
    </match>`

func yamlLine(tabs int, line string, newline bool) string {
	spaces := strings.Repeat(`    `, tabs)
	if !newline {
		return spaces + line
	}
	return spaces + line + "\n"
}

// BuildConfigMap returns a ConfigMap object
func BuildConfigMap(instance *operatorv1alpha1.AuditLogging, name string) (*corev1.ConfigMap, error) {
	reqLogger := log.WithValues("ConfigMap.Namespace", InstanceNamespace, "ConfigMap.Name", name)
	metaLabels := LabelsForMetadata(FluentdName)
	dataMap := make(map[string]string)
	var err error
	var data string
	switch name {
	case FluentdDaemonSetName + "-" + ConfigName:
		dataMap[enableAuditLogForwardKey] = strconv.FormatBool(instance.Spec.Fluentd.EnableAuditLoggingForwarding)
		type Data struct {
			Value string `yaml:"fluent.conf"`
		}
		d := Data{}
		data = buildFluentdConfig(instance)
		err = yaml.Unmarshal([]byte(data), &d)
		dataMap[fluentdConfigKey] = d.Value
	case FluentdDaemonSetName + "-" + SourceConfigName:
		type DataS struct {
			Value string `yaml:"source.conf"`
		}
		ds := DataS{}
		data = buildFluentdSourceConfig(instance)
		err = yaml.Unmarshal([]byte(data), &ds)
		dataMap[sourceConfigKey] = ds.Value
	case FluentdDaemonSetName + "-" + SplunkConfigName:
		type DataSplunk struct {
			Value string `yaml:"splunkHEC.conf"`
		}
		dsplunk := DataSplunk{}
		data = buildFluentdSplunkConfig(instance)
		err = yaml.Unmarshal([]byte(data), &dsplunk)
		if err != nil {
			reqLogger.Error(err, "Failed to unmarshall data for "+name)
		}
		dataMap[splunkConfigKey] = dsplunk.Value
	case FluentdDaemonSetName + "-" + QRadarConfigName:
		type DataQRadar struct {
			Value string `yaml:"remoteSyslog.conf"`
		}
		dq := DataQRadar{}
		data = buildFluentdQRadarConfig(instance)
		err = yaml.Unmarshal([]byte(data), &dq)
		dataMap[qRadarConfigKey] = dq.Value
	default:
		reqLogger.Info("Unknown ConfigMap name")
	}
	if err != nil {
		reqLogger.Error(err, "Failed to unmarshall data for "+name)
		return nil, err
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: InstanceNamespace,
			Labels:    metaLabels,
		},
		Data: dataMap,
	}
	return cm, nil
}

func buildFluentdConfig(instance *operatorv1alpha1.AuditLogging) string {
	var result = fluentdMainConfigData
	if instance.Spec.Fluentd.OutputPlugin.Splunk != (operatorv1alpha1.AuditLoggingSpecSplunk{}) {
		result += yamlLine(1, splunkPlugin, true)
	} else if instance.Spec.Fluentd.OutputPlugin.QRadar != (operatorv1alpha1.AuditLoggingSpecQRadar{}) {
		result += yamlLine(1, qradarPlugin, true)
	}
	return result
}

func buildFluentdSourceConfig(instance *operatorv1alpha1.AuditLogging) string {
	var result string
	if instance.Spec.Fluentd.JournalPath != "" {
		result = sourceConfigData1 + instance.Spec.Fluentd.JournalPath + sourceConfigData2
	} else {
		result = sourceConfigData1 + defaultJournalPath + sourceConfigData2
	}
	var p string
	if res, port := getHTTPPort(instance.Spec.Fluentd.HTTPPort); res {
		p = strconv.Itoa(int(port))
	} else {
		p = strconv.Itoa(defaultHTTPPort)
	}
	result += sourceConfigData3 + p + sourceConfigData4
	return result
}

func buildFluentdSplunkConfig(instance *operatorv1alpha1.AuditLogging) string {
	var result = splunkConfigData
	if instance.Spec.Fluentd.OutputPlugin.Splunk != (operatorv1alpha1.AuditLoggingSpecSplunk{}) {
		result += yamlLine(2, `hec_host `+instance.Spec.Fluentd.OutputPlugin.Splunk.Host, true)
		result += yamlLine(2, `hec_port `+instance.Spec.Fluentd.OutputPlugin.Splunk.Port, true)
		result += yamlLine(2, `hec_token `+instance.Spec.Fluentd.OutputPlugin.Splunk.Token, false)
	} else {
		result += yamlLine(2, `hec_host SPLUNK_SERVER_HOSTNAME`, true)
		result += yamlLine(2, `hec_port SPLUNK_PORT`, true)
		result += yamlLine(2, `hec_token SPLUNK_HEC_TOKEN`, false)
	}
	return result + splunkConfigData2
}

func buildFluentdQRadarConfig(instance *operatorv1alpha1.AuditLogging) string {
	var result = qRadarConfigData
	if instance.Spec.Fluentd.OutputPlugin.QRadar != (operatorv1alpha1.AuditLoggingSpecQRadar{}) {
		result += yamlLine(3, `host `+instance.Spec.Fluentd.OutputPlugin.QRadar.Host, true)
		result += yamlLine(3, `port `+instance.Spec.Fluentd.OutputPlugin.QRadar.Port, true)
		result += yamlLine(3, `hostname `+instance.Spec.Fluentd.OutputPlugin.QRadar.Hostname, false)
	} else {
		result += yamlLine(3, `host QRADAR_SERVER_HOSTNAME`, true)
		result += yamlLine(3, `port QRADAR_PORT_FOR_icp-audit`, true)
		result += yamlLine(3, `hostname QRADAR_LOG_SOURCE_IDENTIFIER_FOR_icp-audit`, false)
	}
	return result + qRadarConfigData2
}

func EqualConfigMaps(expected *corev1.ConfigMap, found *corev1.ConfigMap) bool {
	return !reflect.DeepEqual(expected.Data, found.Data)
}
