# go-nd-portal
Go 你电 portal

## 安装

你可以下载 [已经编译好的二进制文件](https://github.com/fumiama/go-nd-portal/releases).

从源码安装:
```bash
$ go install github.com/fumiama/go-nd-portal@latest
```

## 使用方法

> 也可不带参数运行，会在启动时询问参数

```
./go-nd-portal -n 20xxxxxxxxxxx -p password [-t <TYPE>]
```
默认值：
 * `-ip`: 本机公网出口，可自定义

 * `-t`: 登录类型（`qsh-edu`），可指定为:
    * 清水河，教学办公区: 
      * `qsh-edu`,   教育网  
      * `qsh-dx`,    电信  
    * 清水河，新建宿舍区: 
      * `qshd-dx`,   电信  
      * `qshd-cmcc`, 移动  

 * `-s`: 服务器地址（根据上述登录类型自动选择），可自定义


## 效果

<img alt="screenshot" src="https://github.com/user-attachments/assets/1e4a7f0b-d9c5-4b4e-a5f7-a2f39f7ca3a3">
