// Package portal handles login process
package portal

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/fumiama/go-nd-portal/helper"
)

var (
	// ErrIllegalLoginType is returned when an invalid login type is provided
	ErrIllegalLoginType = errors.New("illegal login type")
	// ErrUnexpectedChallengeResponse is returned when challenge is shorter than expected
	ErrUnexpectedChallengeResponse = errors.New("unexpected challenge response")
	// ErrCannotDetermineClientIP is returned when client IP cant get from challenge or local resolution with cip not specified
	ErrCannotDetermineClientIP = errors.New("failed to determine client IP from challenge response or local resolution")
	// ErrUnexpectedLoginResponse is returned when login resp is shorter than expected
	ErrUnexpectedLoginResponse = errors.New("unexpected login response")
)

// Portal struct for login config
type Portal struct {
	name   string
	pswd   string
	cip    string
	sip    string
	domain string
	acid   string
}

// LoginType defines known login types
type LoginType string

const (
	// LoginTypeQshEdu edu in Qsh work area
	LoginTypeQshEdu LoginType = "qsh-edu"
	// LoginTypeQshDX dx in Qsh work area
	LoginTypeQshDX LoginType = "qsh-dx"
	// LoginTypeQshDormDX dx in Qsh new dorm area
	LoginTypeQshDormDX LoginType = "qshd-dx"
	// LoginTypeQshDormCMCC cmcc in Qsh new dorm area
	LoginTypeQshDormCMCC LoginType = "qshd-cmcc"
	// LoginTypeShEdu edu in Sh
	LoginTypeShEdu LoginType = "sh-edu"
	// LoginTypeShDX dx in Sh
	LoginTypeShDX LoginType = "sh-dx"
	// LoginTypeShCMCC cmcc in Sh
	LoginTypeShCMCC LoginType = "sh-cmcc"
)

// GetDefaultPortalServerIP returns default PortalServerIP by LoginType
func (lt LoginType) GetDefaultPortalServerIP() (string, error) {
	var sIP string
	switch lt {
	// Qsh work area
	case LoginTypeQshEdu, LoginTypeQshDX:
		sIP = PortalServerIPQsh
	// Qsh new dorm area
	case LoginTypeQshDormDX, LoginTypeQshDormCMCC:
		sIP = PortalServerIPQshDorm
	// Sh
	case LoginTypeShEdu, LoginTypeShDX, LoginTypeShCMCC:
		sIP = PortalServerIPSh
	default:
		return "", ErrIllegalLoginType
	}

	return sIP, nil
}

// ToDomainAcID converts LoginType to domain and acid
func (lt LoginType) ToDomainAcID() (string, string, error) {
	var domain, acid string
	switch lt {
	// Qsh work area
	case LoginTypeQshEdu:
		// qsh-edu is assumed that cant login from dorm
		domain = PortalDomainQsh
		acid = AcIDQsh
	case LoginTypeQshDX:
		domain = PortalDomainQshDX
		acid = AcIDQsh
	// Qsh new dorm area
	case LoginTypeQshDormDX:
		domain = PortalDomainQshDX
		acid = AcIDQshDorm
	case LoginTypeQshDormCMCC:
		domain = PortalDomainQshCMCC
		acid = AcIDQshDorm
	// Sh
	case LoginTypeShEdu:
		domain = PortalDomainSh
		acid = AcIDSh
	case LoginTypeShDX:
		domain = PortalDomainShDX
		acid = AcIDSh
	case LoginTypeShCMCC:
		domain = PortalDomainShCMCC
		acid = AcIDSh
	default:
		return "", "", ErrIllegalLoginType
	}

	return domain, acid, nil
}

// ResolveLocalClientIP resolves Client IP locally
func ResolveLocalClientIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
}

// CommonRsp struct for login session specific response
type CommonRsp struct {
	// return code and various messages
	// trash, but we have to add it
	Status     string `json:"error"`
	ErrorMsg   string `json:"error_msg"`
	PloyMsg    string `json:"ploy_msg"`
	SuccessMsg string `json:"suc_msg"`

	// client_ip
	ClientIP   string `json:"client_ip"`
	// online_ip
	OnlineIP   string `json:"online_ip"`
	// challenge
	Challenge  string `json:"challenge"`
}

// Error implements the error interface for CommonRsp
func (cr *CommonRsp) Error() string {
	// handle error msg and code based on priority
	if cr.PloyMsg != "" {
		return cr.PloyMsg
	}
	if cr.ErrorMsg != "" {
		return cr.ErrorMsg
	}
	if cr.Status != "" && cr.Status != "ok" {
		return cr.Status
	}
	// fallback
	return "unknown portal response error"
}

// Err checks if the response indicates an error
func (cr *CommonRsp) Err() error {
	if cr.Status == "ok" {
		// if suc_msg is not login_ok, warn
		if cr.SuccessMsg != "" && cr.SuccessMsg != "login_ok" {
			logrus.Warnln(cr.SuccessMsg)
		}
		return nil
	}
	// cr is wrapped into error
	return cr
}

// NewPortal creates a new Portal instance
func NewPortal(name, password, sIP string, cIP string, loginType LoginType) (*Portal, error) {
	domain, acid, err := loginType.ToDomainAcID()
	if err != nil {
		return nil, err
	}
	logrus.Debugf("login type: %s, portal domain: %s, ac_id: %s", loginType, domain, acid)

	if sIP == "" {
		sIP, err = loginType.GetDefaultPortalServerIP()
		if err != nil {
			return nil, err
		}
	}
	logrus.Debugf("server addr: %s", sIP)

	return &Portal{
		name:   name,
		pswd:   password,
		cip:    cIP,
		sip:    sIP,
		domain: domain,
		acid:   acid,
	}, nil
}

// GetChallenge gets token for encryption from server
func (p *Portal) GetChallenge() (string, error) {
	// Note: no need to do URL encoding here
	u, err := GetChallengeURL(
		p.sip,
		"gondportal",
		p.name,
		p.domain,
		p.cip,
		time.Now().UnixMilli(),
	)

	if err != nil {
		return "", err
	}
	logrus.Debugln("GET", u)
	data, err := requestDataWith(u, "GET", PortalHeaderUA)
	if err != nil {
		return "", err
	}
	logrus.Debugln("get challenge resp:", helper.BytesToString(data))
	if len(data) < 12 {
		return "", ErrUnexpectedChallengeResponse
	}

	var r CommonRsp
	err = json.Unmarshal(data[11:len(data)-1], &r)
	if err != nil {
		return "", err
	}
	err = r.Err()
	// rsp message handling
	if err != nil {
		return "", err
	}

	// if cip was left empty, try get from challenge resp
	if p.cip == "" {
		logrus.Debugln("client ip is not specified, try get client ip from challenge resp")
		_, err = netip.ParseAddr(r.ClientIP)
		if err == nil {
			p.cip = r.ClientIP
			logrus.Debugln("get client ip from challenge resp:", r.ClientIP)
		} else {
			// if ClientIP is invalid, try resolve it locally
			p.cip, err = ResolveLocalClientIP()
			if err != nil {
				return "", ErrCannotDetermineClientIP
			}
			logrus.Debugln("failed to get client ip from challenge resp, using locally resolved ip:", p.cip)
		}
	}
	logrus.Debugln("get challenge:", r.Challenge)
	return r.Challenge, nil
}

// PasswordHMd5 encrypts password with hmacmd5 algorithm
func (p *Portal) PasswordHMd5(challenge string) string {
	var buf [16]byte
	h := hmac.New(md5.New, helper.StringToBytes(challenge))
	_, _ = h.Write(helper.StringToBytes(p.pswd))
	return hex.EncodeToString(h.Sum(buf[:0]))
}

// Login sends login request to server
// input:
// challenge
func (p *Portal) Login(challenge string) error {
	userInfo, err := GetUserInfo(p.name, p.domain, p.pswd, p.cip, p.acid)
	if err != nil {
		return err
	}
	info := EncodeUserInfo(userInfo, challenge)
	hmd5 := p.PasswordHMd5(challenge)
	// Note: no need to do URL encoding here
	u, err := GetLoginURL(
		p.sip,
		"gondportal",
		p.name,
		p.domain,
		hmd5,
		p.acid,
		p.cip,
		p.CheckSum(challenge, p.name, p.domain, hmd5, p.acid, p.cip, info),
		info,
		time.Now().UnixMilli(),
	)

	if err != nil {
		return err
	}
	logrus.Debugln("GET", u)
	data, err := requestDataWith(u, "GET", PortalHeaderUA)
	if err != nil {
		return err
	}
	logrus.Debugln("get login resp:", helper.BytesToString(data))
	if len(data) < 12 {
		return ErrUnexpectedLoginResponse
	}

	var r CommonRsp
	err = json.Unmarshal(data[11:len(data)-1], &r)
	if err != nil {
		return err
	}

	// compare local cip with response client_ip
	if p.cip != r.ClientIP {
		logrus.Warnln("client ip in login request does not match response! unexpected errors may occur")
		logrus.Warnf("request: %s, response: %s", p.cip, r.ClientIP)
	}

	return r.Err()
}
