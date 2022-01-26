package main

import (
	"fmt"
	"github.com/libp2p/go-libp2p-tls/cmd/tlsdiag/client"
	"github.com/libp2p/go-libp2p-tls/cmd/tlsdiag/server"
	"os"
)

func main() {
	if len(os.Args) <= 1 {
		fmt.Println("missing argument: client / server")
		return
	}

	role := os.Args[1]
	// remove the role argument from os.Args
	os.Args = append([]string{os.Args[0]}, os.Args[2:]...)

	var err error
	switch role {
	case "client":
		err = client.StartClient()
	case "server":
		err = server.StartServer()
	default:
		fmt.Println("invalid argument. Expected client / server")
		return
	}
	if err != nil {
		panic(err)
	}
}
