package main

import (
	"errors"
	"flag"
	"math"
	"net"
)

type Config struct {
	strLA   string
	strSA   string
	un      []byte
	pwd     []byte
	unL     int
	pwdL    int
	useAuth bool
	la      *net.TCPAddr
	sa      *net.TCPAddr

	debug bool
	info  bool
}

func NewConfig() (*Config, error) {
	var (
		err  error
		conf *Config
		u    string
		p    string
	)

	conf = &Config{}

	flag.StringVar(&conf.strLA, "la", "", "local address, like :5678")
	flag.StringVar(&conf.strSA, "sa", "", "server address")
	flag.StringVar(&u, "un", "", "username")
	flag.StringVar(&p, "pwd", "", "password")

	flag.BoolVar(&conf.debug, "d", false, "debug")
	flag.BoolVar(&conf.info, "i", false, "output info")

	flag.Parse()

	if conf.strLA == "" {
		return nil, errors.New("local address was missing")
	}

	if conf.strSA == "" {
		return nil, errors.New("server address was missing")
	}

	if u != "" || p != "" {
		conf.useAuth = true
	}

	// the length of username and password must little or equal then MaxUint8
	// see https://tools.ietf.org/html/rfc1929
	if conf.unL = len(u); conf.unL > math.MaxUint8 {
		return nil, errors.New("too large username")
	}

	conf.un = []byte(u)

	if conf.pwdL = len(p); conf.pwdL > math.MaxUint8 {
		return nil, errors.New("too large passowrd")
	}

	conf.pwd = []byte(p)

	if conf.la, err = net.ResolveTCPAddr("tcp", conf.strLA); err != nil {
		return nil, errors.New("invalid local address: " + err.Error())
	}

	if conf.sa, err = net.ResolveTCPAddr("tcp", conf.strSA); err != nil {
		return nil, errors.New("invalid server address: " + err.Error())
	}

	return conf, nil
}
