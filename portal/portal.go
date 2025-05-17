// Package portal handles login process
package portal

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/fumiama/go-nd-portal/helper"
)

var (
	// ErrIllegalIPv4 is returned when an invalid IPv4 address is provided
	ErrIllegalIPv4                 = errors.New("illegal ipv4")
	// ErrIllegalLoginType is returned when an invalid login type is provided
	ErrIllegalLoginType            = errors.New("illegal login type")
	// ErrUnexpectedChallengeResponse is returned when challenge is shorter than expected
	ErrUnexpectedChallengeResponse = errors.New("unexpected challenge response")
	// ErrUnexpectedLoginResponse is returned when login resp is shorter than expected
	ErrUnexpectedLoginResponse     = errors.New("unexpected login response")
)

// Portal struct for login config
type Portal struct {
	nam		string
	pwd		string
	ip		net.IP
	domain	string
	acid	string
}

// rsp struct for converting from raw response data to JSON
type rsp struct {
	Challenge string `json:"challenge"`
	Error     string `json:"error"`
}

// NewPortal creates a new Portal instance
func NewPortal(name, password string, ipv4 net.IP, loginType string) (*Portal, error) {
	if len(ipv4) != 4 {
		return nil, ErrIllegalIPv4
	}

	var domain, acid string
	switch loginType {
		case "qsh-edu":
			// qsh-edu is assumed that cant login from dorm
			domain = PortalDomainQsh
			acid = AcIDQsh
		case "qsh-dx":
			domain = PortalDomainQshDX
			acid = AcIDQsh
		case "qshd-dx":
			domain = PortalDomainQshDX
			acid = AcIDQshDorm
		case "qshd-cmcc":
			domain = PortalDomainQshCMCC
			acid = AcIDQshDorm
		default:
			return nil, ErrIllegalLoginType
	}
	logrus.Debugln(fmt.Sprintf("portal domain: %s, ac_id: %s", domain, acid))
	return &Portal{
		nam:	name,
		pwd:	password,
		ip:		ipv4,
		domain: domain,
		acid:	acid,
	}, nil
}

// GetChallenge gets token for encryption from server
// input:
// server IP
func (p *Portal) GetChallenge(sIP string) (string, error) {
	// 1.PortalServerIP 2. callback 3.username 4.PortalDomain 
	// 5.client IP 6.timestamp
	// Note: no need to do URL encoding here
	u, err := GetChallengeURL(sIP, "gondportal", p.nam, p.domain, p.ip, time.Now().UnixMilli())
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
	_, _ = h.Write(helper.StringToBytes(p.pwd))
	return hex.EncodeToString(h.Sum(buf[:0]))
}

// Login sends login request to server
// input: 
// server IP
// challenge
func (p *Portal) Login(sIP, challenge string) error {
	// 1. username 2.PortalDomain 3. client IP 4. ac_id
	userInfo, err := GetUserInfo(p.nam, p.domain, p.pwd, p.ip, p.acid)
	if err != nil {
		return err
	}
	info := EncodeUserInfo(userInfo, challenge)
	hmd5 := p.PasswordHMd5(challenge)
	// 1.PortalServerIP 2. callback 3.username 4.PortalDomain 
	// 5.encrypted password 
	// 6.ac_id: determined by login type
	// 7.client IP
	// 8.checksum
	// 9.info
	// 10.timestamp
	// Note: no need to do URL encoding here
	u, err := GetLoginURL(sIP, "gondportal", p.nam, p.domain, hmd5, p.acid, p.ip, p.CheckSum(p.domain, challenge, hmd5, p.acid, info), info, time.Now().UnixMilli())
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
