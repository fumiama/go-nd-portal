package portal

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/fumiama/go-nd-portal/helper"
)

func TestDecodeInfo(t *testing.T) {
	info := `{"username":"2000010101001@dx-uestc","password":"12345678","ip":"1.2.3.4","acid":"1","enc_ver":"srun_bx1"}`
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
	assert.Equal(t, []uint32{1937056379, 1634628197, 975332717, 808464930, 808529968, 808529969, 1681928496, 1702178168, 576943219, 1634738732, 1870099315, 975332466, 858927394, 926299444, 573317688, 975335529, 841888034, 875442990, 1629629474, 577005923, 573645370, 1852121644, 1702256483, 574235250, 1853190771, 829973087, 32034, 106}, v)
}

func TestDecodeKey(t *testing.T) {
	challenge := "c312a4194d4310695b71d92ac3c740198a14a7a280022f89408edec4e932d1e5"
	sc := len(challenge)
	k := make([]uint32, sc/4)
	token := helper.StringToBytes(challenge)
	for i := 0; i < sc/4; i++ {
		k[i] = binary.LittleEndian.Uint32(token[i*4 : i*4+4])
	}
	assert.Equal(t, []uint32{842085219, 959525985, 859071540, 959852593, 825713205, 1630681444, 929248099, 959524916, 875651384, 845231969, 842018872, 959997490, 1698181172, 878929252, 842217829, 895824228}, k)
}

func TestEncodeUserInfo(t *testing.T) {
	u, err := NewPortal("2001010101001", "1234567890", net.IPv4(113, 54, 148, 243).To4())
	if err != nil {
		t.Fatal(err)
	}
	t.Log(u.String())
	r := EncodeUserInfo(u.String(), "d26466d4036507dadb17e87e23358126e0210cb289d19151f59bcfcefdcf345e")
	assert.Equal(t, "CfVnZ9mvKmdgvm/ivovlPibZL6RLAWcx+nBTaYmWH3kmThco+eO4LVsCPFceSmM9PyI0UcMgLE7bmpfY9pr0EWnWdTncXrbW29Aydp+lw6QjxKMgNzgYd7uopiPbIyKpxvJZDHsGw5xh8rMEeq3JXrD2vex27xeI", r)
}

func TestHMd5(t *testing.T) {
	u, err := NewPortal("2001010101001", "1234567890", net.IPv4(113, 54, 148, 243).To4())
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "91062ae815fb02d9d15aec834aafffd4", u.PasswordHMd5("d26466d4036507dadb17e87e23358126e0210cb289d19151f59bcfcefdcf345e"))
}

func TestSha1(t *testing.T) {
	h := sha1.New()
	h.Write([]byte("123456"))
	assert.Equal(t, "7c4a8d09ca3762af61e59520943dc26494f8941b", hex.EncodeToString(h.Sum(nil)))
}

func TestCheckSum(t *testing.T) {
	u, err := NewPortal("2001010101001", "1234567890", net.IPv4(113, 54, 148, 243).To4())
	if err != nil {
		t.Fatal(err)
	}
	t.Log(u.String())
	challenge := "d26466d4036507dadb17e87e23358126e0210cb289d19151f59bcfcefdcf345e"
	s := u.CheckSum(
		PortalDomain,
		challenge,
		u.PasswordHMd5(challenge),
		EncodeUserInfo(
			u.String(),
			challenge,
		),
	)
	assert.Equal(t, "64e8913b6019df98e3b807343b8785856909d745", s)
}
