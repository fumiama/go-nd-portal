package portal

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

var client = &http.Client{}

// requestDataWith 使用自定义请求头获取数据
func requestDataWith(url, method, ua string) (data []byte, err error) {
	// 提交请求
	var request *http.Request
	request, err = http.NewRequest(method, url, nil)
	if err == nil {
		// 增加header选项
		if ua != "" {
			request.Header.Add("User-Agent", ua)
		}
		var response *http.Response
		response, err = client.Do(request)
		if err == nil {
			if response.StatusCode != http.StatusOK {
				s := fmt.Sprintf("status code: %d", response.StatusCode)
				err = errors.New(s)
				return
			}
			data, err = io.ReadAll(response.Body)
			response.Body.Close()
		}
	}
	return
}
