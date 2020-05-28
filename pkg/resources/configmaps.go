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
	"errors"
	"regexp"
	"strconv"
	"strings"

	operatorv1alpha1 "github.com/ibm/ibm-auditlogging-operator/pkg/apis/operator/v1alpha1"
	yaml "gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const EnableAuditLogForwardKey = "ENABLE_AUDIT_LOGGING_FORWARDING"

var qradarPlugin = `@include /fluentd/etc/remoteSyslog.conf`
var splunkPlugin = `@include /fluentd/etc/splunkHEC.conf`

// ConfigName defines the name of the config configmap
const ConfigName = "config"

// FluentdConfigName defines the name of the volume for the config configmap
const FluentdConfigName = "main-config"

// SourceConfigName defines the name of the source-config configmap
const SourceConfigName = "source-config"

// QRadarConfigName defines the name of the remote-syslog-config configmap
const QRadarConfigName = "remote-syslog-config"

// SplunkConfigName defines the name of the splunk-hec-config configmap
const SplunkConfigName = "splunk-hec-config"

const FluentdConfigKey = "fluent.conf"

// SourceConfigKey defines the key for the source-config configmap
const SourceConfigKey = "source.conf"

// SplunkConfigKey defines the key for the splunk-hec-config configmap
const SplunkConfigKey = "splunkHEC.conf"

//QRadarConfigKey defines the key for the remote-syslog-config configmap
const QRadarConfigKey = "remoteSyslog.conf"

// OutputPluginMatches defines the match tags for Splunk and QRadar outputs
const OutputPluginMatches = "icp-audit icp-audit.**"

var fluentdMainConfigData = `
fluent.conf: |-
    # Input plugins (Supports Systemd and HTTP)
    @include /fluentd/etc/source.conf

    # Output plugins (Only use one output plugin conf file at a time.
`

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
    </filter>
    <filter icp-audit.*>
        @type record_transformer
        enable_ruby true
        <record>
          tag ${tag}
          message ${record.to_json}
        </record>
    </filter>`

var splunkConfigData1 = `
splunkHEC.conf: |-
    <match icp-audit icp-audit.**>
        @type splunk_hec
`

// FIX
// var splunkDefaults = `
//         hec_host SPLUNK_SERVER_HOSTNAME
//         hec_port SPLUNK_PORT
//         hec_token SPLUNK_HEC_TOKEN
//         ca_file /fluentd/etc/tls/splunkCA.pem
//         source ${tag}`
var splunkConfigData2 = `
    </match>`

var qRadarConfigData1 = `
remoteSyslog.conf: |-
    <match icp-audit icp-audit.**>
        @type copy
        <store>
            @type remote_syslog
`

// FIX
// var qRadarDefaults = `
//             host QRADAR_SERVER_HOSTNAME
//             port QRADAR_PORT_FOR_icp-audit
//             hostname QRADAR_LOG_SOURCE_IDENTIFIER_FOR_icp-audit
//             protocol tcp
//             tls true
//             ca_file /fluentd/etc/tls/qradar.crt
//             packet_size 4096
//             program fluentd
//             <format>
//                 @type single_value
//                 message_key message
//             </format>
//         </store>`
var qRadarConfigData2 = `
    </match>`

// DataSplunk defines the struct for splunk-hec-config
type DataSplunk struct {
	Value string `yaml:"splunkHEC.conf"`
}

// DataQRadar defines the struct for remote-syslog-config
type DataQRadar struct {
	Value string `yaml:"remoteSyslog.conf"`
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
		dataMap[EnableAuditLogForwardKey] = strconv.FormatBool(instance.Spec.Fluentd.EnableAuditLoggingForwarding)
		type Data struct {
			Value string `yaml:"fluent.conf"`
		}
		d := Data{}
		data = buildFluentdConfig(instance)
		err = yaml.Unmarshal([]byte(data), &d)
		dataMap[FluentdConfigKey] = d.Value
	case FluentdDaemonSetName + "-" + SourceConfigName:
		type DataS struct {
			Value string `yaml:"source.conf"`
		}
		ds := DataS{}
		var result string
		if instance.Spec.Fluentd.JournalPath != "" {
			result = sourceConfigData1 + instance.Spec.Fluentd.JournalPath + sourceConfigData2
		} else {
			result = sourceConfigData1 + defaultJournalPath + sourceConfigData2
		}
		p := strconv.Itoa(defaultHTTPPort)
		result += sourceConfigData3 + p + sourceConfigData4
		err = yaml.Unmarshal([]byte(result), &ds)
		dataMap[SourceConfigKey] = ds.Value
	case FluentdDaemonSetName + "-" + SplunkConfigName:
		dsplunk := DataSplunk{}
		data = buildFluentdSplunkConfig(instance)
		err = yaml.Unmarshal([]byte(data), &dsplunk)
		if err != nil {
			reqLogger.Error(err, "Failed to unmarshall data for "+name)
		}
		dataMap[SplunkConfigKey] = dsplunk.Value
	case FluentdDaemonSetName + "-" + QRadarConfigName:
		dq := DataQRadar{}
		data = buildFluentdQRadarConfig(instance)
		err = yaml.Unmarshal([]byte(data), &dq)
		dataMap[QRadarConfigKey] = dq.Value
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

func getConfig(data string) (string, error) {
	var siemConfig string
	// >([^]]+)< retrieves all data between match tags
	regex := `>\n([^]]+)\n<`
	reConfig := regexp.MustCompile(regex)
	matches := reConfig.FindStringSubmatch(data)
	if len(matches) < 2 {
		return "", errors.New("output plugin config misformatted")
	}
	config := matches[1]
	lines := strings.Split(config, "\n")
	var tabs = 1
	for i, line := range lines {
		if i < len(lines)-1 {
			siemConfig += yamlLine(tabs, line, true)
		} else {
			siemConfig += yamlLine(tabs, line, false)
		}
	}
	return siemConfig, nil
}

func EqualSIEMConfig(instance *operatorv1alpha1.AuditLogging, found *corev1.ConfigMap) bool {
	var key string
	if instance.Spec.Fluentd.Output.Splunk != (operatorv1alpha1.AuditLoggingSpecSplunk{}) {
		key = SplunkConfigKey
		reHost := regexp.MustCompile(`hec_host .*`)
		hostFound := reHost.FindStringSubmatch(found.Data[key])[0]
		if hostFound != instance.Spec.Fluentd.Output.Splunk.Host {
			return false
		}
		rePort := regexp.MustCompile(`hec_port .*`)
		portFound := rePort.FindStringSubmatch(found.Data[key])[0]
		if portFound != strconv.Itoa(instance.Spec.Fluentd.Output.Splunk.Port) {
			return false
		}
		reToken := regexp.MustCompile(`hec_token .*`)
		tokenFound := reToken.FindStringSubmatch(found.Data[key])[0]
		if tokenFound != instance.Spec.Fluentd.Output.Splunk.Token {
			return false
		}
	} else if instance.Spec.Fluentd.Output.QRadar != (operatorv1alpha1.AuditLoggingSpecQRadar{}) {
		key = QRadarConfigKey
		reHost := regexp.MustCompile(`host .*`)
		hostFound := reHost.FindStringSubmatch(found.Data[key])[0]
		if hostFound != instance.Spec.Fluentd.Output.QRadar.Host {
			return false
		}
		rePort := regexp.MustCompile(`port .*`)
		portFound := rePort.FindStringSubmatch(found.Data[key])[0]
		if portFound != strconv.Itoa(instance.Spec.Fluentd.Output.QRadar.Port) {
			return false
		}
		reToken := regexp.MustCompile(`hostname .*`)
		hostnameFound := reToken.FindStringSubmatch(found.Data[key])[0]
		if hostnameFound != instance.Spec.Fluentd.Output.QRadar.Hostname {
			return false
		}
	}
	return true
}

func removeK8sAudit(data string) string {
	// K8s auditing was deprecated in CS 3.2.4 and removed in CS 3.3
	return strings.Split(data, "<match kube-audit>")[0]
}

func yamlLine(tabs int, line string, newline bool) string {
	spaces := strings.Repeat(`    `, tabs)
	if !newline {
		return spaces + line
	}
	return spaces + line + "\n"
}

func buildFluentdConfig(instance *operatorv1alpha1.AuditLogging) string {
	var result = fluentdMainConfigData
	if instance.Spec.Fluentd.Output.Splunk != (operatorv1alpha1.AuditLoggingSpecSplunk{}) {
		result += yamlLine(1, splunkPlugin, true)
	} else if instance.Spec.Fluentd.Output.QRadar != (operatorv1alpha1.AuditLoggingSpecQRadar{}) {
		result += yamlLine(1, qradarPlugin, true)
	}
	return result
}

func buildFluentdSplunkConfig(instance *operatorv1alpha1.AuditLogging) string {
	var result = splunkConfigData1
	if instance.Spec.Fluentd.Output.Splunk != (operatorv1alpha1.AuditLoggingSpecSplunk{}) {
		result += yamlLine(2, `hec_host `+instance.Spec.Fluentd.Output.Splunk.Host, true)
		result += yamlLine(2, `hec_port `+strconv.Itoa(instance.Spec.Fluentd.Output.Splunk.Port), true)
		result += yamlLine(2, `hec_token `+instance.Spec.Fluentd.Output.Splunk.Token, false)
	} else {
		result += yamlLine(2, `hec_host SPLUNK_SERVER_HOSTNAME`, true)
		result += yamlLine(2, `hec_port SPLUNK_PORT`, true)
		result += yamlLine(2, `hec_token SPLUNK_HEC_TOKEN`, false)
	}
	// need to add user customized configs like buffer ?
	return result + splunkConfigData2
}

func buildFluentdQRadarConfig(instance *operatorv1alpha1.AuditLogging) string {
	var result = qRadarConfigData1
	if instance.Spec.Fluentd.Output.QRadar != (operatorv1alpha1.AuditLoggingSpecQRadar{}) {
		result += yamlLine(3, `host `+instance.Spec.Fluentd.Output.QRadar.Host, true)
		result += yamlLine(3, `port `+strconv.Itoa(instance.Spec.Fluentd.Output.QRadar.Port), true)
		result += yamlLine(3, `hostname `+instance.Spec.Fluentd.Output.QRadar.Hostname, false)
	} else {
		result += yamlLine(3, `host QRADAR_SERVER_HOSTNAME`, true)
		result += yamlLine(3, `port QRADAR_PORT_FOR_icp-audit`, true)
		result += yamlLine(3, `hostname QRADAR_LOG_SOURCE_IDENTIFIER_FOR_icp-audit`, false)
	}
	// need to add user customized configs like buffer ?
	return result + qRadarConfigData2
}

// BuildWithSIEMConfigs returns a String and an Error
func BuildWithSIEMConfigs(found *corev1.ConfigMap) (string, error) {
	var result string
	var err error
	var siemConfig string
	if found.Name == FluentdDaemonSetName+"-"+SplunkConfigName {
		siemConfig, err = getConfig(found.Data[SplunkConfigKey])
		if err != nil {
			return "", err
		}
		ds := DataSplunk{}
		err = yaml.Unmarshal([]byte(splunkConfigData1+"\n"+siemConfig+splunkConfigData2), &ds)
		result = ds.Value
	} else {
		data := removeK8sAudit(found.Data[QRadarConfigKey])
		siemConfig, err = getConfig(data)
		if err != nil {
			return "", err
		}
		dq := DataQRadar{}
		err = yaml.Unmarshal([]byte(qRadarConfigData1+"\n"+siemConfig+qRadarConfigData2), &dq)
		result = dq.Value
	}
	return result, err
}

// EqualMatchTags returns a Boolean
func EqualMatchTags(found *corev1.ConfigMap) bool {
	logger := log.WithValues("func", "EqualMatchTags")
	var key string
	if found.Name == FluentdDaemonSetName+"-"+SplunkConfigName {
		key = SplunkConfigKey
	} else {
		key = QRadarConfigKey
	}
	re := regexp.MustCompile(`match icp-audit icp-audit\.\*\*`)
	var match = re.FindStringSubmatch(found.Data[key])
	if len(match) < 1 {
		logger.Info("Match tags not equal", "Expected", OutputPluginMatches)
		return false
	}
	return len(match) >= 1
}

// EqualSourceConfig returns a Boolean and a String slice
func EqualSourceConfig(expected *corev1.ConfigMap, found *corev1.ConfigMap) (bool, []string) {
	var ports []string
	var foundPort string
	re := regexp.MustCompile("port [0-9]+")
	var match = re.FindStringSubmatch(found.Data[SourceConfigKey])
	if len(match) < 1 {
		foundPort = ""
	} else {
		foundPort = strings.Split(match[0], " ")[1]
	}
	ports = append(ports, foundPort)
	match = re.FindStringSubmatch(expected.Data[SourceConfigKey])
	expectedPort := strings.Split(match[0], " ")[1]
	return (foundPort == expectedPort), append(ports, expectedPort)
}
