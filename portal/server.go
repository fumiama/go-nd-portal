package portal

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"

	"github.com/fumiama/go-nd-portal/base64"
	"github.com/fumiama/go-nd-portal/helper"
)

const (
	PortalServerIP       = "10.253.0.237"
	PortalDomain         = "@dx-uestc"
	PortalDomainDX       = "@dx"
	PortalGetChallenge   = "http://" + PortalServerIP + "/cgi-bin/get_challenge?callback=%s&username=%s" + PortalDomain + "&ip=%v&_=%d"
	PortalGetChallengeDX = "http://" + PortalServerIP + "/cgi-bin/get_challenge?callback=%s&username=%s" + PortalDomainDX + "&ip=%v&_=%d"
	PortalLogin          = "http://" + PortalServerIP + "/cgi-bin/srun_portal?callback=%s&action=login&username=%s" + PortalDomain + "&password={MD5}%s&ac_id=1&ip=%v&chksum=%s&info={SRBX1}%s&n=200&type=1&os=Windows+10&name=Windows&double_stack=0&_=%d"
	PortalLoginDX        = "http://" + PortalServerIP + "/cgi-bin/srun_portal?callback=%s&action=login&username=%s" + PortalDomainDX + "&password={MD5}%s&ac_id=1&ip=%v&chksum=%s&info={SRBX1}%s&n=200&type=1&os=Windows+10&name=Windows&double_stack=0&_=%d"
)

const (
	PortalHeaderUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 Edg/107.0.1418.56"
)

const (
	PortalUserInfo   = `{"username":"%s` + PortalDomain + `","password":"%s","ip":"%v","acid":"1","enc_ver":"srun_bx1"}`
	PortalUserInfoDX = `{"username":"%s` + PortalDomainDX + `","password":"%s","ip":"%v","acid":"1","enc_ver":"srun_bx1"}`
)

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

func (p *Portal) CheckSum(domain, challenge, hmd5, info string) string {
	var buf [20]byte
	h := sha1.New()
	_, _ = h.Write(helper.StringToBytes(challenge))
	_, _ = h.Write(helper.StringToBytes(p.nam))
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write(helper.StringToBytes(challenge))
	_, _ = h.Write(helper.StringToBytes(hmd5))
	_, _ = h.Write(helper.StringToBytes(challenge))
	_, _ = h.Write([]byte("1")) // ac_id
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
