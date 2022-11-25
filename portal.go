package gondportal

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/FloatTech/floatbox/web"
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

func (p *Portal) GetChallenge() (string, error) {
	data, err := web.RequestDataWith(
		web.NewDefaultClient(),
		fmt.Sprintf(PortalGetChallenge, "gondportal", p.nam, p.ip, time.Now().UnixMilli()),
		"GET", "", PortalHeaderUA,
	)
	if err != nil {
		return "", err
	}
	if len(data) < 12 {
		return "", ErrUnexpectedChallengeResponse
	}
	type rsp struct {
		Challenge string `json:"challenge"`
		Ecode     int    `json:"ecode"`
		Msg       string `json:"error_msg"`
	}
	var r rsp
	err = json.Unmarshal(data[11:len(data)-1], &r)
	if err != nil {
		return "", err
	}
	if r.Ecode != 0 {
		return "", errors.New(r.Msg)
	}
	return r.Challenge, nil
}

func (p *Portal) PasswordHMd5(challenge string) string {
	var buf [16]byte
	h := hmac.New(md5.New, StringToBytes(challenge))
	_, _ = h.Write(StringToBytes(p.pwd))
	return hex.EncodeToString(h.Sum(buf[:0]))
}

func (p *Portal) Login(challenge string) error {
	info := EncodeUserInfo(p.String(), challenge)
	hmd5 := p.PasswordHMd5(challenge)
	data, err := web.RequestDataWith(
		web.NewDefaultClient(),
		fmt.Sprintf(PortalLogin, "gondportal", p.nam, hmd5, p.ip, p.CheckSum(challenge, hmd5, info), info, time.Now().UnixMilli()),
		"GET", "", PortalHeaderUA,
	)
	if err != nil {
		return err
	}
	if len(data) < 12 {
		return ErrUnexpectedLoginResponse
	}
	type rsp struct {
		Error string `json:"error"`
	}
	var r rsp
	err = json.Unmarshal(data[11:len(data)-1], &r)
	if err != nil {
		return err
	}
	if r.Error == "ok" {
		return nil
	}
	return errors.New(r.Error)
}

func (p *Portal) String() string {
	return fmt.Sprintf(PortalUserInfo, p.nam, p.pwd, p.ip)
}
