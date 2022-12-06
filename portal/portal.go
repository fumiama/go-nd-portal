package portal

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/fumiama/go-nd-portal/helper"
)

var (
	ErrIllegalIPv4                 = errors.New("illegal ipv4")
	ErrUnexpectedChallengeResponse = errors.New("unexpected challenge response")
	ErrUnexpectedLoginResponse     = errors.New("unexpected login response")
)

type Portal struct {
	nam string
	pwd string
	ip  net.IP
}

type rsp struct {
	Challenge string `json:"challenge"`
	Error     string `json:"error"`
}

func NewPortal(name, password string, ipv4 net.IP) (*Portal, error) {
	if len(ipv4) != 4 {
		return nil, ErrIllegalIPv4
	}
	return &Portal{
		nam: name,
		pwd: password,
		ip:  ipv4,
	}, nil
}

func (p *Portal) GetChallenge(u string) (string, error) {
	u = fmt.Sprintf(u, "gondportal", url.QueryEscape(p.nam), p.ip, time.Now().UnixMilli())
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

func (p *Portal) PasswordHMd5(challenge string) string {
	var buf [16]byte
	h := hmac.New(md5.New, helper.StringToBytes(challenge))
	_, _ = h.Write(helper.StringToBytes(p.pwd))
	return hex.EncodeToString(h.Sum(buf[:0]))
}

func (p *Portal) Login(u, domain, challenge string) error {
	info := EncodeUserInfo(p.String(), challenge)
	hmd5 := p.PasswordHMd5(challenge)
	u = fmt.Sprintf(u, "gondportal", url.QueryEscape(p.nam), hmd5, p.ip, p.CheckSum(domain, challenge, hmd5, info), url.QueryEscape(info), time.Now().UnixMilli())
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

func (p *Portal) String() string {
	return fmt.Sprintf(PortalUserInfo, p.nam, p.pwd, p.ip)
}
