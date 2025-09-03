package portal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAutoSelectServerIP(t *testing.T) {
	u, err := NewPortal("2000010101001", "12345678", "", "1.2.3.4", LoginTypeQshEdu)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(LoginTypeQshEdu, u.sip)
	assert.Equal(t, PortalServerIPQsh, u.sip)

	u, err = NewPortal("2000010101001", "12345678", "", "1.2.3.4", LoginTypeQshDormDX)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(LoginTypeQshDormDX, u.sip)
	assert.Equal(t, PortalServerIPQshDorm, u.sip)

	u, err = NewPortal("2000010101001", "12345678", "", "1.2.3.4", LoginTypeShEdu)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(LoginTypeShEdu, u.sip)
	assert.Equal(t, PortalServerIPSh, u.sip)
}

func TestResolveLocalClientIP(t *testing.T) {
	cip, err := ResolveLocalClientIP()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(cip)
}
