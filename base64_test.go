package gondportal

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBase64(t *testing.T) {
	buf := strings.Builder{}
	base64.NewEncoder(Base64Encoding, &buf).Write([]byte("123456"))
	assert.Equal(t, "9F2z0JHI", buf.String())
}
