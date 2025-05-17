// Package base64 with customized talbe
package base64

import b64 "encoding/base64"

const (
	// PortalBase64Table customized order
	PortalBase64Table = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
)

// Base64Encoding of customized
var Base64Encoding = b64.NewEncoding(PortalBase64Table)
