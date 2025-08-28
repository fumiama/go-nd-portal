// Package cmd interacts with user
package cmd

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"runtime"

	"golang.org/x/term"

	"github.com/sirupsen/logrus"

	"github.com/fumiama/go-nd-portal/helper"
	"github.com/fumiama/go-nd-portal/portal"
)

func line() int {
	_, _, fileLine, ok := runtime.Caller(1)
	if ok {
		return fileLine
	}
	return -1
}

const query = "query"

// Main cmd program
func Main() {
	ip := flag.String("ip", "", "client IP, auto get from login host when empty")
	n := flag.String("n", query, "username")
	p := flag.String("p", query, "password")
	h := flag.Bool("h", false, "display this help")
	w := flag.Bool("w", false, "only display warn-or-higher-level log")
	d := flag.Bool("d", false, "display debug-level log")
	s := flag.String("s", "", "login host, auto select when empty")
	t := flag.String("t", "qsh-edu", "login type [qsh-edu | qsh-dx | qshd-dx | qshd-cmcc]")
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
	if *ip != "" {
		// just validate IP here,
		// dont convert to net.IP because we need only its string later
		_, err := netip.ParseAddr(*ip)
		if err != nil {
			logrus.Errorln(err)
			os.Exit(line())
		}
	}
	if *n == query {
		fmt.Printf("username: ")
		_, err := fmt.Scanln(n)
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
	if *s != "" {
		// just validate IP here,
		// dont convert to net.IP because we need only its string later
		_, err := netip.ParseAddr(*s)
		if err != nil {
			logrus.Errorln(err)
			os.Exit(line())
		}
	}
	// n : username
	// p: password
	// ip : public ip
	// *t : login type
	ptl, err := portal.NewPortal(*n, *p, *s, *ip, portal.LoginType(*t))
	if err != nil {
		logrus.Errorln(err)
		os.Exit(line())
	}
	challenge, err := ptl.GetChallenge()
	if err != nil {
		logrus.Errorln(err)
		os.Exit(line())
	}
	// input:
	// challenge
	err = ptl.Login(challenge)
	if err != nil {
		logrus.Errorln(err)
		os.Exit(line())
	}
	logrus.Infoln("success")
}
