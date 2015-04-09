package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"github.com/mconintet/clicolor"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
)

const (
	connect        = "CONNECT"
	errMissingPort = "missing port in address"
	version5       = byte(5)
	authBare       = byte(0)
	authUnPwd      = byte(2)

	connectCmd = byte(1)
	rsv        = byte(0)
	aTypIPv4   = byte(1)
	aTypIPv6   = byte(4)
	aTypDomain = byte(3)

	repSucceed = byte(0)

	unPwdVersion = byte(1)
	unPwdSucceed = byte(0)
)

var idSeed = uint64(0)

type conn struct {
	id         uint64
	server     *Server
	nc         net.Conn          // client conn
	cbr        *bufio.Reader     // buffer reader for client conn
	ctp        *textproto.Reader // textprotp reader for client conn
	isConnect  bool
	ss         *net.TCPConn // conn to socks5 server
	authMethod byte
	readBuf    *bytes.Buffer

	isNcDone chan int // if nc has been closed
	isSsDone chan int // if ss has been closed
}

func newConn(nc net.Conn, server *Server) (*conn, error) {
	c := new(conn)

	atomic.AddUint64(&idSeed, uint64(1))
	c.id = atomic.LoadUint64(&idSeed)

	c.server = server
	c.nc = nc
	c.cbr = bufio.NewReader(nc)
	c.ctp = textproto.NewReader(c.cbr)

	c.readBuf = bytes.NewBuffer([]byte{})

	c.isNcDone = make(chan int)
	c.isSsDone = make(chan int)

	return c, nil
}

func parseRequestLine(line string) (method, requestURI, proto string, ok bool) {
	s1 := strings.Index(line, " ")
	s2 := strings.Index(line[s1+1:], " ")
	if s1 < 0 || s2 < 0 {
		return
	}
	s2 += s1 + 1
	return line[:s1], line[s1+1 : s2], line[s2+1:], true
}

func (c *conn) processHostPortConnect(requestUri string) (host string, port string, err error) {
	c.isConnect = true
	// if this is a CONNECT request we need to discard proxy headers
	c.ctp.ReadMIMEHeader()

	if host, port, err = net.SplitHostPort(requestUri); err != nil {
		return "", "", err
	}

	return host, port, nil
}

func (c *conn) processHostPortNormal(requestUri string) (host string, port string, err error) {
	// RFC2616: Must treat
	//	GET /index.html HTTP/1.1
	//	Host: www.google.com
	// and
	//	GET http://www.google.com/index.html HTTP/1.1
	//	Host: doesntmatter
	// the same.  In the second case, any Host line is ignored.

	var (
		header textproto.MIMEHeader
		s      string
		pu     *url.URL
		ae     *net.AddrError
		ok     bool
		h      http.Header
	)

	if header, err = c.ctp.ReadMIMEHeader(); err != nil {
		goto errReturn
	}

	if strings.HasPrefix(requestUri, "/") {
		if s = header.Get("Host"); s == "" {
			err = errors.New("request uri start with '/' but missing header 'Host'")
			goto errReturn
		}

		if host, port, err = net.SplitHostPort(s); err != nil {
			goto errReturn
		}
	} else {
		if pu, err = url.Parse(requestUri); err != nil {
			goto errReturn
		}

		if host, port, err = net.SplitHostPort(pu.Host); err != nil {
			if ae, ok = err.(*net.AddrError); ok && ae.Err == errMissingPort {
				host = pu.Host
				port = "80"
			} else {
				goto errReturn
			}
		}
	}

	if s = header.Get("Proxy-Connection"); s != "" {
		header.Del("Proxy-Connection")
		header.Set("Connection", s)
	}

	h = http.Header(header)
	h.Write(c.readBuf)
	c.readBuf.Write([]byte("\r\n"))

	return host, port, nil

errReturn:
	return "", "", nil
}

func (c *conn) processHostPort() (host string, port string, err error) {
	var (
		s          string
		ok         bool
		method     string
		requestUri string
	)

	// read first line
	if s, err = c.ctp.ReadLine(); err != nil {
		return "", "", errors.New("failed to read first line: " + err.Error())
	}

	// store the read first line
	c.readBuf.Write([]byte(s + "\r\n"))

	if method, requestUri, _, ok = parseRequestLine(s); !ok {
		return "", "", errors.New("invalid request line")
	}

	c.info(requestUri)

	if method == connect {
		return c.processHostPortConnect(requestUri)
	}

	return c.processHostPortNormal(requestUri)
}

func (c *conn) makeShakeHandMethodSelection() []byte {
	var (
		b = []byte{version5, 1, authBare}
	)

	if c.server.Conf.useAuth {
		b[2] = authUnPwd
	}

	c.authMethod = b[2]
	return b
}

func (c *conn) authUnPwd() error {
	var (
		err error
		b   = []byte{unPwdVersion, byte(c.server.Conf.unL)}
	)

	b = append(b, c.server.Conf.un...)
	b = append(b, byte(c.server.Conf.pwdL))
	b = append(b, c.server.Conf.pwd...)

	if _, err = c.ss.Write(b); err != nil {
		return err
	}

	if _, err = c.ss.Read(b[:2]); err != nil {
		return err
	}

	if b[1] != unPwdSucceed {
		return errors.New("invalid username or password")
	}

	return nil
}

func (c *conn) makeSocks5Command(host, port string) ([]byte, error) {
	var (
		b         = []byte{version5, connectCmd, rsv}
		ip        net.IP
		ip4       net.IP
		ip6       net.IP
		aTyp      byte
		n         int
		portInt   int
		portInt16 uint16
		err       error
	)

	ip = net.ParseIP(host)
	if ip == nil {
		aTyp = aTypDomain
	} else if ip4 = ip.To4(); ip4 != nil {
		aTyp = aTypIPv4
	} else if ip6 = ip.To16(); ip6 != nil {
		aTyp = aTypIPv6
	}

	switch aTyp {
	case aTypDomain:
		if n = len(host); n > math.MaxUint8 {
			return nil, errors.New("too large doamin")
		}

		b = append(b, aTypDomain)
		b = append(b, byte(n))
		b = append(b, []byte(host)...)

		goto appendPort
	case aTypIPv4:
		b = append(b, aTypIPv4)
		b = append(b, []byte(ip4)...)
		goto appendPort
	case aTypIPv6:
		b = append(b, aTypIPv6)
		b = append(b, []byte(ip6)...)
		goto appendPort
	}

	return nil, errors.New("un-caught error")

appendPort:
	if portInt, err = strconv.Atoi(port); err != nil {
		return nil, err
	}

	portInt16 = uint16(portInt)
	b = append(b, byte(portInt16>>8))
	b = append(b, byte(portInt16))

	return b, nil
}

func (c *conn) readCmdReplay() error {
	var (
		err error
		// replay bytes length must be little then this number: 263 = 1 + 1 + 1 + 1 + ( 1 + 256 ) + 2
		buf = make([]byte, 263)
	)

	if _, err = c.ss.Read(buf); err != nil {
		return err
	}

	if buf[1] != repSucceed {
		return errors.New("command rejected, server replay: " + strconv.Itoa(int(buf[1])))
	}

	return nil
}

func (c *conn) shakeHandWithSocks5Server() error {
	var (
		err  error
		b    []byte
		buf  = make([]byte, 2)
		cmd  []byte
		host string
		port string
	)

	c.log("shaking hand with socks5 server")

	// dial socks5 server
	if c.ss, err = net.DialTCP("tcp", nil, c.server.Conf.sa); err != nil {
		return errors.New("failed to dial socks5 server: " + err.Error())
	}

	// make and send method selection
	b = c.makeShakeHandMethodSelection()
	if _, err = c.ss.Write(b); err != nil {
		return errors.New("failed to send method selection: " + err.Error())
	}

	// check whether server support our methods or not
	if _, err = c.ss.Read(buf); err != nil {
		return errors.New("failed to read replay of method selection: " + err.Error())
	}

	if buf[1] != c.authMethod {
		return errors.New("server doesn't support auth method: " + strconv.Itoa(int(c.authMethod)))
	}

	// need to do sub-negotiate
	if buf[1] == authUnPwd {
		if err = c.authUnPwd(); err != nil {
			return errors.New("sub-negotiate error: " + err.Error())
		}
	}

	// make and send command
	if host, port, err = c.processHostPort(); err != nil {
		return errors.New("failed to parse host:port " + err.Error())
	}

	if cmd, err = c.makeSocks5Command(host, port); err != nil {
		return errors.New("failed to make command: " + err.Error())
	}

	if _, err = c.ss.Write(cmd); err != nil {
		return errors.New("failed to send command: " + err.Error())
	}

	// read server replay to check whether server allow our command or not
	if err = c.readCmdReplay(); err != nil {
		return errors.New("failed to read replay of command: " + err.Error())
	}

	return nil
}

func (c *conn) connectShakeHand() {
	c.nc.Write([]byte(`HTTP/1.0 200 Connection established
Proxy-agent: honey/0.1

`))
}

func (c *conn) transfer() error {
	var (
		err  error
		err1 error
		err2 error
	)

	if !c.isConnect {
		// send bytes read by "honey" to remote server
		if _, err = c.readBuf.WriteTo(c.ss); err != nil {
			return errors.New("failed to send read bytes to server: " + err.Error())
		}
	} else {
		c.connectShakeHand()
	}

	c.log("transfering")

	// right to left
	go func() {
		_, err2 = io.Copy(c.nc, c.ss)
		c.isSsDone <- 1
	}()

	// left to right
	go func() {
		_, err1 = io.Copy(c.ss, c.nc)
		c.isNcDone <- 1
	}()

	select {
	case <-c.isNcDone:
		c.log(clicolor.Colorize("l2r done", "green", "black"))
	case <-c.isSsDone:
		c.log(clicolor.Colorize("r2l done", "green", "black"))

	}

	if err1 != nil {
		return errors.New("l2r error: " + err1.Error())
	}

	if err2 != nil && err2 != io.EOF {
		return errors.New("r2l error: " + err2.Error())
	}

	return nil
}

func (c *conn) close() {
	if c.nc != nil {
		c.nc.Close()
	}

	if c.ss != nil {
		c.ss.Close()
	}

	c.log("honey conn closed")
}

func (c *conn) serve() {
	var (
		err error
	)

	defer c.close()

	c.log(clicolor.Colorize("new conn", "green", "black"))

	if err = c.shakeHandWithSocks5Server(); err != nil {
		c.log(err)
		return
	}

	c.log("shake hand with Socks5 server OK")

	if err = c.transfer(); err != nil {
		c.log(err)
	}
}

func (c *conn) info(arg interface{}) {
	if c.server.Conf.info {
		info := fmt.Sprintf("info: %v", arg)
		log.Printf(clicolor.Colorize(info, "yellow", "black"))
	}
}

func (c *conn) log(args interface{}) {
	if c.server.Conf.debug {
		log.Printf("CONN ["+strconv.FormatUint(c.id, 10)+"]: %v", args)
	}
}
