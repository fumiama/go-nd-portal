package cmd

import (
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"time"

	"golang.org/x/term"

	"github.com/sirupsen/logrus"

	"github.com/fumiama/go-nd-portal/helper"
	"github.com/fumiama/go-nd-portal/portal"
)

func outip() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return nil, err
	}
	_ = conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.To4(), nil
}

func line() int {
	_, _, fileLine, ok := runtime.Caller(1)
	if ok {
		return fileLine
	}
	return -1
}

const query = "query"

func Main() {
	ip, err := outip()
	ipf := ""
	if err != nil {
		ipf = query
	} else {
		ipf = ip.String()
	}
	ips := flag.String("ip", ipf, "public IP")
	n := flag.String("n", query, "username")
	p := flag.String("p", query, "password")
	h := flag.Bool("h", false, "display this help")
	w := flag.Bool("w", false, "only display warn-or-higher-level log")
	d := flag.Bool("d", false, "display debug-level log")
	flag.Parse()
	if *h {
		fmt.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(0)
	}
	if *d {
		logrus.SetLevel(logrus.DebugLevel)
	} else if *w {
		logrus.SetLevel(logrus.WarnLevel)
	}
	if *ips == query {
		fmt.Printf("ip: ")
		_, err = fmt.Scanln(ips)
		if err != nil {
			logrus.Errorln(err)
			os.Exit(line())
		}
	}
	if *ips != ip.String() {
		ipaddr, err := netip.ParseAddr(*ips)
		if err != nil {
			logrus.Errorln(err)
			os.Exit(line())
		}
		a4 := ipaddr.As4()
		copy(ip, a4[:])
	}
	if *n == query {
		fmt.Printf("username: ")
		_, err = fmt.Scanln(n)
		if err != nil {
			logrus.Errorln(err)
			os.Exit(line())
		}
	}
	if *p == query {
		fmt.Printf("password: ")
		data, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			logrus.Errorln(err)
			os.Exit(line())
		}
		*p = helper.BytesToString(data)
		fmt.Println()
	}
	portal, err := portal.NewPortal(*n, *p, ip)
	if err != nil {
		logrus.Errorln(err)
		os.Exit(line())
	}
	challenge, err := portal.GetChallenge()
	if err != nil {
		logrus.Errorln(err)
		os.Exit(line())
	}
	time.Sleep(time.Second + time.Duration(time.Now().Unix()%1000)*time.Millisecond)
	err = portal.Login(challenge)
	if err != nil {
		logrus.Errorln(err)
		os.Exit(line())
	}
	logrus.Infoln("success")
}
