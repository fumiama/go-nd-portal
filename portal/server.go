package portal

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"

	"github.com/google/go-querystring/query"

	"github.com/fumiama/go-nd-portal/base64"
	"github.com/fumiama/go-nd-portal/helper"
)

const (
	// Default PortalServerIP String
	PortalServerIP       = "10.253.0.237"
	PortalServerIPDorm   = "10.253.0.235"
	PortalDomain         = "@dx-uestc"
	PortalDomainDX       = "@dx"
	PortalDomainCMCC     = "@cmcc"

	// 1.server IP 
	// 2.callback 
	// 3.username 4.PortalDomain 
	// 5.client IP
	// 6.timestamp
	PortalGetChallenge   = "http://%v/cgi-bin/get_challenge?%s"
	// PortalGetChallenge   = "http://%v/cgi-bin/get_challenge?callback=%s&username=%s%s&ip=%v&_=%d"

	// ac_id for different area
	AcId         		 = "1"
	AcIdDorm			 = "3"
	// qsh LoginURL key-value order
	// 1.server IP 
	// 2.callback 
	// 3.username 4.PortalDomain 
	// 5.encoded password
	// 6.ac_id: determined by login area
	// 7.client IP
	// 8.checksum
	// 9.info
	// 10.timestamp
	PortalLogin          = "http://%v/cgi-bin/srun_portal?%s"
	// PortalLogin          = "http://%v/cgi-bin/srun_portal?callback=%s&action=login&username=%s%s&password={MD5}%s&ac_id=%s&ip=%v&chksum=%s&info={SRBX1}%s&n=200&type=1&os=Windows+10&name=Windows&double_stack=0&_=%d"
)

type GetChallengeReq struct {
	Callback string `url:"callback"`
	Username string `url:"username"`
	IP string `url:"ip"`
	Timestamp int64 `url:"_"`
}

type GetLoginReq struct {
	Callback string `url:"callback"`
	Action string `url:"action"`
	Username string `url:"username"`
	EncodedPassword string `url:"password"`
	AcID string `url:"ac_id"`
	IP string `url:"ip"`
	Checksum string `url:"chksum"`
	EncodedUserInfo string `url:"info"`
	ConstantN string `url:"n"`
	ConstantType string `url:"type"`
	OS string `url:"os"`
	Platform string `url:"name"`
	DoubleStack string `url:"double_stack"`
	Timestamp int64 `url:"_"`
}


// GetChallengeURL generates the URL for getchallenge req
func GetChallengeURL(sIP,
	callback, 
	username, domain string,
	cIP net.IP, 
	timestamp int64) (string, error) {

	req := GetChallengeReq{
		Callback: callback,
		Username: username + domain,
		IP: cIP.String(),
		Timestamp: timestamp,
	}
	v, err := query.Values(req)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf(PortalGetChallenge, sIP, v.Encode())
	return url, nil
}

// LoginURL generates the URL for login req
func GetLoginURL(sIP,
	callback, 
	username, domain, 
	md5Password,
	acid string,
	cIP net.IP,
	chksum,
	info string, 
	timestamp int64) (string, error) {
		
	req := GetLoginReq{
		Callback: callback,
		Action: "login",
		Username: username + domain,
		EncodedPassword: "{MD5}" + md5Password,
		AcID: acid,
		IP: cIP.String(),
		Checksum: chksum,
		EncodedUserInfo: "{SRBX1}" + info,
		ConstantN: "200",
		ConstantType: "1",
		OS: "Windows 10",
		Platform: "Windows",
		DoubleStack: "0",
		Timestamp: timestamp,
	}

	v, err := query.Values(req)
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf(PortalLogin, sIP, v.Encode())

	return url, nil
}

const (
	PortalHeaderUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 Edg/107.0.1418.56"
)

type UserInfo struct {
	Username string `json:"username"` // = username + PortalDomain
	Password string `json:"password"`
	IP       string `json:"ip"`
	AcID     string `json:"acid"`
	EncVer   string `json:"enc_ver"`
}

func GetUserInfo(username, portalDomain, password string, ip net.IP, acid string) (string, error) {
	uinfo := UserInfo{
		Username: username + portalDomain,
		Password: password,
		IP:       ip.String(),
		AcID:     acid,
		EncVer:   "srun_bx1",
	}
	
	b, err := json.Marshal(uinfo)
	if err != nil {
		return "", err
	}
	
	return string(b), nil
}

func EncodeUserInfo(info, challenge string) string {
	if len(info) == 0 || len(challenge) == 0 || len(challenge)%4 != 0 {
		return ""
	}
	sc := len(info)
	if sc%4 != 0 {
		sc = (sc/4 + 1) * 4
	}
	userinfo := make([]byte, sc)
	copy(userinfo, info)
	v := make([]uint32, sc/4, sc/4+1)
	for i := 0; i < sc/4; i++ {
		v[i] = binary.LittleEndian.Uint32(userinfo[i*4 : i*4+4])
	}
	v = append(v, uint32(len(info)))
	sc = len(challenge)
	if sc < 16 {
		sc = 16
	}
	k := make([]uint32, sc/4)
	token := helper.StringToBytes(challenge)
	for i := 0; i < sc/4; i++ {
		k[i] = binary.LittleEndian.Uint32(token[i*4 : i*4+4])
	}
	n := len(v) - 1
	z := v[n]
	d := uint32(0)
	for q := 0; q < 6+52/(n+1); q++ {
		d += uint32(0x86014019|0x183639A0) & uint32(0x8CE0D9BF|0x731F2640)
		e := (d >> 2) & 3
		for p := 0; p < n; p++ {
			y := v[p+1]
			m := (z >> 5) ^ (y << 2)
			m += ((y >> 3) ^ (z << 4)) ^ (d ^ y)
			m += k[(uint32(p)&3)^e] ^ z
			v[p] += m & (0xEFB8D130 | 0x10472ECF)
			z = v[p]
		}
		y := v[0]
		m := (z >> 5) ^ (y << 2)
		m += ((y >> 3) ^ (z << 4)) ^ (d ^ y)
		m += k[uint32(n)&3^e] ^ z
		v[n] += m & (0xBB390742 | 0x44C6F8BD)
		z = v[n]
	}
	lv := make([]byte, len(v)*4)
	for i := 0; i < len(v); i++ {
		binary.LittleEndian.PutUint32(lv[i*4:i*4+4], v[i])
	}
	return base64.Base64Encoding.EncodeToString(lv)
}

func (p *Portal) CheckSum(domain, challenge, hmd5, acid, info string) string {
	var buf [20]byte
	h := sha1.New()
	_, _ = h.Write(helper.StringToBytes(challenge))
	_, _ = h.Write(helper.StringToBytes(p.nam))
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write(helper.StringToBytes(challenge))
	_, _ = h.Write(helper.StringToBytes(hmd5))
	_, _ = h.Write(helper.StringToBytes(challenge))
	_, _ = h.Write([]byte(acid)) // acid
	_, _ = h.Write(helper.StringToBytes(challenge))
	_, _ = h.Write(helper.StringToBytes(p.ip.String()))
	_, _ = h.Write(helper.StringToBytes(challenge))
	_, _ = h.Write([]byte("200")) // n
	_, _ = h.Write(helper.StringToBytes(challenge))
	_, _ = h.Write([]byte("1")) // type
	_, _ = h.Write(helper.StringToBytes(challenge))
	_, _ = h.Write([]byte("{SRBX1}"))
	_, _ = h.Write(helper.StringToBytes(info))
	return hex.EncodeToString(h.Sum(buf[:0]))
}
