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
	t.Log(u.sip)
	assert.Equal(t, PortalServerIPQsh, u.sip)
}
