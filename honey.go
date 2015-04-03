package main

import (
	"log"
)

func main() {
	var (
		err    error
		conf   *Config
		server *Server
	)

	if conf, err = NewConfig(); err != nil {
		log.Fatal(err)
	}

	server = &Server{conf}
	server.IncreaseRlimit()

	if err = server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
