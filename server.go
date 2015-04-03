package main

import (
	"log"
	"net"
	"syscall"
)

type Server struct {
	Conf *Config
}

func (s *Server) ListenAndServe() error {
	var (
		err error
		l   net.Listener
	)

	if l, err = net.ListenTCP("tcp", s.Conf.la); err != nil {
		return err
	}

	return s.Serve(l)
}

func (s *Server) Serve(l net.Listener) error {
	defer l.Close()

	var (
		err error
		nc  net.Conn
		ne  net.Error
		ok  bool
		c   *conn
	)

	for {
		if nc, err = l.Accept(); err != nil {
			if ne, ok = err.(net.Error); ok && ne.Temporary() {
				continue
			}

			return err
		}

		if c, err = newConn(nc, s); err != nil {
			continue
		}

		go c.serve()
	}
}

func (s *Server) IncreaseRlimit() {
	var (
		err error
		lim *syscall.Rlimit
	)

	// details: http://linux.die.net/man/2/setrlimit
	lim = &syscall.Rlimit{
		65535,
		65535,
	}

	// details: http://stackoverflow.com/questions/17817204/how-to-set-ulimit-n-from-a-golang-program
	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, lim)
	if err != nil {
		log.Println("Error occrred when increasing rlimit: " + err.Error())
		log.Fatal("You may need to run this soft as root.")
	}
}
