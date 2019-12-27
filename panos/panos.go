// Package panos interacts with Palo Alto and Panorama devices using the XML API.
package panos

import (
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"github.com/parnurzeal/gorequest"
	"strings"
	"context"
)

// PaloAlto is a container for our session state. It also holds information about the device
// that is gathered upon a successful connection to it.
type PaloAlto struct {
	Host                       string
	Key                        string
	URI                        string
	Platform                   string
	Model                      string
	Serial                     string
	SoftwareVersion            string
	DeviceType                 string
	Panorama                   bool
	Shared                     bool
	IPAddress                  string
	Netmask                    string
	DefaultGateway             string
	MACAddress                 string
	Time                       string
	Uptime                     string
	GPClientPackageVersion     string
	GPDatafileVersion          string
	GPDatafileReleaseDate      string
	GPClientlessVPNVersion     string
	GPClientlessVPNReleaseDate string
	AppVersion                 string
	AppReleaseDate             string
	AntiVirusVersion           string
	AntiVirusReleaseDate       string
	ThreatVersion              string
	ThreatReleaseDate          string
	WildfireVersion            string
	WildfireReleaseDate        string
	URLDB                      string
	URLFilteringVersion        string
	LogDBVersion               string
	MultiVsys                  string
	OperationalMode            string
}

// AuthMethod defines how we want to authenticate to the device. If using a
// username and password to authenticate, the Credentials field must contain the username and password
//, respectively (e.g. []string{"admin", "password"}). If you are using the API key for
// authentication, provide the entire key for the APIKey field.
type AuthMethod struct {
	Credentials []string
	APIKey      string
}

// authKey holds our API key.
type authKey struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Key     string   `xml:"result>key"`
}

// systemInfo holds basic system information.
type systemInfo struct {
	XMLName                    xml.Name `xml:"response"`
	Status                     string   `xml:"status,attr"`
	Code                       string   `xml:"code,attr"`
	Platform                   string   `xml:"result>system>platform-family"`
	Model                      string   `xml:"result>system>model"`
	Serial                     string   `xml:"result>system>serial"`
	SoftwareVersion            string   `xml:"result>system>sw-version"`
	IPAddress                  string   `xml:"result>system>ip-address"`
	Netmask                    string   `xml:"result>system>netmask"`
	DefaultGateway             string   `xml:"result>system>default-gateway"`
	MACAddress                 string   `xml:"result>system>mac-address"`
	Time                       string   `xml:"result>system>time"`
	Uptime                     string   `xml:"result>system>uptime"`
	GPClientPackageVersion     string   `xml:"result>system>global-protect-client-package-version"`
	GPDatafileVersion          string   `xml:"result>system>global-protect-datafile-version"`
	GPDatafileReleaseDate      string   `xml:"result>system>global-protect-datafile-release-date"`
	GPClientlessVPNVersion     string   `xml:"result>system>global-protect-clientless-vpn-version"`
	GPClientlessVPNReleaseDate string   `xml:"result>system>global-protect-clientless-vpn-release-date"`
	AppVersion                 string   `xml:"result>system>app-version"`
	AppReleaseDate             string   `xml:"result>system>app-release-date"`
	AntiVirusVersion           string   `xml:"result>system>av-version"`
	AntiVirusReleaseDate       string   `xml:"result>system>av-release-date"`
	ThreatVersion              string   `xml:"result>system>threat-version"`
	ThreatReleaseDate          string   `xml:"result>system>threat-release-date"`
	WildfireVersion            string   `xml:"result>system>wildfire-version"`
	WildfireReleaseDate        string   `xml:"result>system>wildfire-release-date"`
	URLDB                      string   `xml:"result>system>url-db"`
	URLFilteringVersion        string   `xml:"result>system>url-filtering-version"`
	LogDBVersion               string   `xml:"result>system>logdb-version"`
	MultiVsys                  string   `xml:"result>system>multi-vsys"`
	OperationalMode            string   `xml:"result>system>operational-mode"`
}

// commandOutput holds the results of our operational mode commands that were issued.

var (
	r = gorequest.New().TLSClientConfig(&tls.Config{InsecureSkipVerify: true})

	errorCodes = map[string]string{
		"400": "Bad request - Returned when a required parameter is missing, an illegal parameter value is used",
		"403": "Forbidden - Returned for authentication or authorization errors including invalid key, insufficient admin access rights",
		"1":   "Unknown command - The specific config or operational command is not recognized",
		"2":   "Internal error - Check with technical support when seeing these errors",
		"3":   "Internal error - Check with technical support when seeing these errors",
		"4":   "Internal error - Check with technical support when seeing these errors",
		"5":   "Internal error - Check with technical support when seeing these errors",
		"6":   "Bad Xpath - The xpath specified in one or more attributes of the command is invalid. Check the API browser for proper xpath values",
		"7":   "Object not present - Object specified by the xpath is not present. For example, entry[@name=’value’] where no object with name ‘value’ is present",
		"8":   "Object not unique - For commands that operate on a single object, the specified object is not unique",
		"9":   "Internal error - Check with technical support when seeing these errors",
		"10":  "Reference count not zero - Object cannot be deleted as there are other objects that refer to it. For example, address object still in use in policy",
		"11":  "Internal error - Check with technical support when seeing these errors",
		"12":  "Invalid object - Xpath or element values provided are not complete",
		"13":  "Operation failed - A descriptive error message is returned in the response",
		"14":  "Operation not possible - Operation is not possible. For example, moving a rule up one position when it is already at the top",
		"15":  "Operation denied - For example, Admin not allowed to delete own account, Running a command that is not allowed on a passive device",
		"16":  "Unauthorized - The API role does not have access rights to run this query",
		"17":  "Invalid command - Invalid command or parameters",
		"18":  "Malformed command - The XML is malformed",
		"19":  "Success - Command completed successfully",
		"20":  "Success - Command completed successfully",
		"21":  "Internal error - Check with technical support when seeing these errors",
		"22":  "Session timed out - The session for this query timed out",
	}
)

// NewSession sets up our connection to the Palo Alto firewall or Panorama device. The authmethod parameter
// is used to define two ways of authenticating to the device. One is via username/password, the other is with
// the API key if you already have generated it. Please see the documentation for the AuthMethod struct for further
// details.
func NewPanosClient(host string, authmethod *AuthMethod) (*PaloAlto, error) {
	var keygen authKey
	var key string
	var info systemInfo
	status := false
	deviceType := "panos"

	if len(authmethod.Credentials) > 0 {
		_, body, errs := r.Get(fmt.Sprintf("https://%s/api/?type=keygen&user=%s&password=%s", host, authmethod.Credentials[0], authmethod.Credentials[1])).End()
		if errs != nil {
			return nil, errs[0]
		}

		err := xml.Unmarshal([]byte(body), &keygen)
		if err != nil {
			return nil, err
		}

		if keygen.Status != "success" {
			return nil, fmt.Errorf("error code %s: %s (keygen)", keygen.Code, errorCodes[keygen.Code])
		}

		key = keygen.Key
	}

	if len(authmethod.APIKey) > 0 {
		key = authmethod.APIKey
	}

	uri := fmt.Sprintf("https://%s/api/?", host)
	_, getInfo, errs := r.Get(fmt.Sprintf("%s&key=%s&type=op&cmd=<show><system><info></info></system></show>", uri, key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	err := xml.Unmarshal([]byte(getInfo), &info)
	if err != nil {
		return nil, err
	}

	if info.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s (show system info)", info.Code, errorCodes[info.Code])
	}

	return &PaloAlto{
		Host:                       host,
		Key:                        key,
		URI:                        fmt.Sprintf("https://%s/api/?", host),
		Platform:                   info.Platform,
		Model:                      info.Model,
		Serial:                     info.Serial,
		SoftwareVersion:            info.SoftwareVersion,
		DeviceType:                 deviceType,
		Panorama:                   status,
		Shared:                     false,
		IPAddress:                  info.IPAddress,
		Netmask:                    info.Netmask,
		DefaultGateway:             info.DefaultGateway,
		MACAddress:                 info.MACAddress,
		Time:                       strings.Trim(info.Time, "[\r\n]"),
		Uptime:                     info.Uptime,
		GPClientPackageVersion:     info.GPClientPackageVersion,
		GPDatafileVersion:          info.GPDatafileVersion,
		GPDatafileReleaseDate:      info.GPDatafileReleaseDate,
		GPClientlessVPNVersion:     info.GPClientlessVPNVersion,
		GPClientlessVPNReleaseDate: info.GPClientlessVPNReleaseDate,
		AppVersion:                 info.AppVersion,
		AppReleaseDate:             info.AppReleaseDate,
		AntiVirusVersion:           info.AntiVirusVersion,
		AntiVirusReleaseDate:       info.AntiVirusReleaseDate,
		ThreatVersion:              info.ThreatVersion,
		ThreatReleaseDate:          info.ThreatReleaseDate,
		WildfireVersion:            info.WildfireVersion,
		WildfireReleaseDate:        info.WildfireReleaseDate,
		URLDB:                      info.URLDB,
		URLFilteringVersion:        info.URLFilteringVersion,
		LogDBVersion:               info.LogDBVersion,
		MultiVsys:                  info.MultiVsys,
		OperationalMode:            info.OperationalMode,
	}, nil
}

// GetGlobalCounterData() will   get all counter data for global counter

type GlobalCounterEntryData struct {
	Category string  `xml:"category"`
	Name     string  `xml:"name"`
	Value    float64 `xml:"value"`
	Rate     string  `xml:"rate"`
	Aspect   string  `xml:"aspect"`
	Desc     string  `xml:"desc"`
	ID       string  `xml:"id"`
	Severity string  `xml:"severity"`
}

type GlobalCounterEntries struct {
	GlobalCounterEntriesData []GlobalCounterEntryData `xml:"entry"`
}

type GlobalCounters struct {
	GlobalCountersData GlobalCounterEntries `xml:"counters,omitempty"`
	T                  float64              `xml:t`
}

type GlobalCounterResponse struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Result  struct {
		DP            string         `xml:"dp,omitempty"`
		GlobalCounter GlobalCounters `xml:"global,omitempty"`
	} `xml:"result"`
}

func (p *PaloAlto) GetGlobalCounterData(ctx context.Context) (GlobalCounterResponse, error) {
	_,gCancel := context.WithCancel(ctx) 
	defer gCancel()
	var globalCounterResponse GlobalCounterResponse
	command := "<show><counter><global></global></counter></show>"
	_, res, errs := r.Get(fmt.Sprintf("%s&key=%s&type=op&cmd=%s", p.URI, p.Key, command)).End()
	if errs != nil {
		return globalCounterResponse, errs[0]
	}

	err := xml.Unmarshal([]byte(res), &globalCounterResponse)
	if err != nil {
		return globalCounterResponse, err
	}
	return globalCounterResponse, nil
}

// GetInterfaceCounterData() will get counter data for interfaces

type IfnetEntryData struct {
	Icmp_Frag  float64 `xml:"icmp_frag"`
	Ifwderrors float64 `xml:"ifwderrors"`
	Ierrors    float64 `xml:"ierrors"`
	Macspoof   float64 `xml:"macspoof"`
	Pod        float64 `xml:"pod"`
	Flowstate  float64 `xml:"flowstate"`
	Ipspoof    float64 `xml:"ipspoof"`
	Teardrop   float64 `xml:"teardrop"`
	Ibytes     float64 `xml:"ibytes"`
	Noarp      float64 `xml:"noarp"`
	Sctp_Conn  float64 `xml:"sctp_conn"`
	Noroute    float64 `xml:"noroute"`
	Noneigh    float64 `xml:"noneigh"`
	Nomac      float64 `xml:"nomac"`
	L2_Encap   float64 `xml:"l2_encap"`
	Zonechange float64 `xml:"zonechange"`
	Other_Conn float64 `xml:"other_conn"`
	Obytes     float64 `xml:"obytes"`
	Land       float64 `xml:"land"`
	Name       string  `xml:"name"`
	Tcp_Conn   float64 `xml:"tcp_conn"`
	Neighpend  float64 `xml:"neighpend"`
	Ipackets   float64 `xml:"ipackets"`
	Opackets   float64 `xml:"opackets"`
	L2_Decap   float64 `xml:"l2_decap"`
	Udp_Conn   float64 `xml:"udp_conn"`
	Idrops     float64 `xml:"idrops"`
}

type IfnetCounters struct {
	IfnetCountersData []IfnetEntryData `xml:"entry"`
}

type HwEntryData struct {
	Obytes       float64 `xml:"obytes"`
	Name         string  `xml:"name"`
	Idrops       float64 `xml:"idrops"`
	Ipackets     float64 `xml:"ipackets"`
	Opackets     float64 `xml:"opackets"`
	Ierrors      float64 `xml:"ierrors"`
	Ibytes       float64 `xml:"ibytes"`
	Tx_Unicast   float64 `xml:"port>tx-unicast"`
	Tx_Multicast float64 `xml:"port>tx-multicast"`
	Rx_Broadcast float64 `xml:"port>rx-broadcast"`
	Rx_Unicast   float64 `xml:"port>rx-unicast"`
	Rx_Multicast float64 `xml:"port>rx-multicast"`
	Rx_Bytes     float64 `xml:"port>rx-bytes"`
	Tx_Broadcast float64 `xml:"port>tx-broadcast"`
	Tx_Bytes     float64 `xml:"port>tx-bytes"`
}

type HwCounters struct {
	HwCountersData []HwEntryData `xml:"entry"`
}

type InterfaceCounterResponse struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Result  struct {
		IfnetCounter IfnetCounters `xml:"ifnet>ifnet,omitempty"`
		HwCounter    HwCounters    `xml:"hw,omitempty"`
	} `xml:"result"`
}

func (p *PaloAlto) GetInterfaceCounterData(ctx context.Context) (InterfaceCounterResponse, error) {
	_,iCancel := context.WithCancel(ctx) 
	defer iCancel()
	var interfaceCounterResponse InterfaceCounterResponse
	command := "<show><counter><interface>all</interface></counter></show>"
	_, res, errs := r.Get(fmt.Sprintf("%s&key=%s&type=op&cmd=%s", p.URI, p.Key, command)).End()
	if errs != nil {
		return interfaceCounterResponse, errs[0]
	}

	err := xml.Unmarshal([]byte(res), &interfaceCounterResponse)
	if err != nil {
		return interfaceCounterResponse, err
	}
	return interfaceCounterResponse, nil
}

// data processor resource utilization

type CPULoadAverageEntryData struct {
	CoreID string  `xml:"coreid"`
	Value  float64 `xml:"value"`
}

type CPULoadMaximumEntryData struct {
	CoreID string  `xml:"coreid"`
	Value  float64 `xml:"value"`
}

type CPULoadByGroupData struct {
	Pktlog_forwarding string `xml:"pktlog_forwarding,omitempty"`
	Flow_lookup       string `xml:"flow_lookup,omitempty"`
	Flow_fastpath     string `xml:"flow_fastpath,omitempty"`
	Flow_np           string `xml:"flow_np,omitempty"`
	Aho_result        string `xml:"aho_result,omitempty"`
	Zip_result        string `xml:"zip_result,omitempty"`
	Flow_host         string `xml:"flow_host,omitempty"`
	Flow_forwarding   string `xml:"flow_forwarding,omitempty"`
	Module_internal   string `xml:"module_internal,omitempty"`
	Flow_ctrl         string `xml:"flow_ctrl,omitempty"`
	Lwm               string `xml:"lwm,omitempty"`
	Flow_slowpath     string `xml:"flow_slowpath,omitempty"`
	Dfa_result        string `xml:"dfa_result,omitempty"`
	Nac_result        string `xml:"nac_result,omitempty"`
	Flow_mgmt         string `xml:'flow_mgmt,omitempty'`
}
type ResourceUtilizationEntryData struct {
	Name  string  `xml:name`
	Value float64 `xml:value`
}


type DataProcessorResourceUtilData struct {
	CPULoadAverage         []*CPULoadAverageEntryData         `xml:"cpu-load-average>entry"`
	CPULoadByGroup 				 *CPULoadByGroupData `xml:"task"`
	CPULoadMaximum         []*CPULoadMaximumEntryData         `xml:"cpu-load-maximum>entry"`
	ResourceUtilization    []*ResourceUtilizationEntryData    `xml:"resource-utilization>entry"`
}
// in most cases, the system only have 1 data processor, and use interval second to grabe the resource util data
type DataProcessorsResourceUtilResponse struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Result  struct {
		DataProcessorsResourceUtil DataProcessorResourceUtilData `xml:"resource-monitor>data-processors>dp0>second"` 
	} `xml:"result"`
}

func (p *PaloAlto) GetDataProcessorsResourceUtilData(ctx context.Context) (DataProcessorsResourceUtilResponse, error) {
	_,dCancel := context.WithCancel(ctx) 
	defer dCancel()
	var dataProcessorsResourceUtilResponse DataProcessorsResourceUtilResponse
	command := "<show><running><resource-monitor><second><last>1</last></second></resource-monitor></running></show>"
	_, res, errs := r.Get(fmt.Sprintf("%s&key=%s&type=op&cmd=%s", p.URI, p.Key, command)).End()
	if errs != nil {
		return dataProcessorsResourceUtilResponse, errs[0]
	}
	err := xml.Unmarshal([]byte(res), &dataProcessorsResourceUtilResponse)
	if err != nil {
		return dataProcessorsResourceUtilResponse, err
	}
	return dataProcessorsResourceUtilResponse, nil
}
