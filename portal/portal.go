// Package portal handles login process
package portal

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/fumiama/go-nd-portal/helper"
)

var (
	// ErrIllegalIPv4 is returned when an invalid IPv4 address is provided
	ErrIllegalIPv4 = errors.New("illegal ipv4")
	// ErrIllegalLoginType is returned when an invalid login type is provided
	ErrIllegalLoginType = errors.New("illegal login type")
	// ErrUnexpectedChallengeResponse is returned when challenge is shorter than expected
	ErrUnexpectedChallengeResponse = errors.New("unexpected challenge response")
	// ErrUnexpectedLoginResponse is returned when login resp is shorter than expected
	ErrUnexpectedLoginResponse = errors.New("unexpected login response")
)

// Portal struct for login config
type Portal struct {
	name   string
	pswd   string
	cip    net.IP
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
)

// GetDefaultPortalServerIP returns default PortalServerIP by LoginType
func (lt LoginType) GetDefaultPortalServerIP() (string, error) {
	var sIP string
	switch lt {
	case LoginTypeQshEdu, LoginTypeQshDX:
		sIP = PortalServerIPQsh
	case LoginTypeQshDormDX, LoginTypeQshDormCMCC:
		sIP = PortalServerIPQshDorm
	default:
		return "", ErrIllegalLoginType
	}

	return sIP, nil
}

// ToDomainAcID converts LoginType to domain and acid
func (lt LoginType) ToDomainAcID() (string, string, error) {
	var domain, acid string
	switch lt {
	case LoginTypeQshEdu:
		// qsh-edu is assumed that cant login from dorm
		domain = PortalDomainQsh
		acid = AcIDQsh
	case LoginTypeQshDX:
		domain = PortalDomainQshDX
		acid = AcIDQsh
	case LoginTypeQshDormDX:
		domain = PortalDomainQshDX
		acid = AcIDQshDorm
	case LoginTypeQshDormCMCC:
		domain = PortalDomainQshCMCC
		acid = AcIDQshDorm
	default:
		return "", "", ErrIllegalLoginType
	}

	return domain, acid, nil
}

// rsp struct for converting from raw response data to JSON
type rsp struct {
	Challenge string `json:"challenge"`
	Error     string `json:"error"`
}

// NewPortal creates a new Portal instance
func NewPortal(name, password, sIP string, cIP net.IP, loginType LoginType) (*Portal, error) {
	if len(cIP) != 4 {
		return nil, ErrIllegalIPv4
	}

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
	var r rsp
	err = json.Unmarshal(data[11:len(data)-1], &r)
	if err != nil {
		return "", err
	}
	if r.Error != "ok" {
		return "", errors.New(r.Error)
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
	var r rsp
	err = json.Unmarshal(data[11:len(data)-1], &r)
	if err != nil {
		return err
	}
	logrus.Debugln("login rsp:", &r)
	if r.Error != "ok" {
		return errors.New(r.Error)
	}
	return nil
}
