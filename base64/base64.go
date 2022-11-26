package base64

import b64 "encoding/base64"

const (
	PortalBase64Table = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
)

var Base64Encoding = b64.NewEncoding(PortalBase64Table)
