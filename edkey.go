package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/michaelbeam/cli"
	ed "golang.org/x/crypto/ed25519"
)

var (
	// PubKey Public Key
	PubKey ed.PublicKey

	// SecKey Secret Key
	SecKey ed.PrivateKey
)

func init() {
	if p, err := hex.DecodeString("fc2b5ecfd5ac1292bc39a393adfc1aeb76fc1d5bd5227737308523da370c5291"); err != nil {
		log.Fatal(err)
	} else {
		PubKey = p
	}
	if s, err := hex.DecodeString("f1acb1538eb99067786e9a341bae5dea347a005329879b2204ae06512eb5b3effc2b5ecfd5ac1292bc39a393adfc1aeb76fc1d5bd5227737308523da370c5291"); err != nil {
		log.Fatal(err)
	} else {
		SecKey = s
	}
}

func main() {
	c := cli.New()
	c.HelpMsg = "edkey sign|verify|create"
	c.HandleFunc("create", create)
	c.HandleFunc("sign", sign)
	c.HandleFunc("verify", verify)
	c.Execute(os.Args[1:])
}

func create(args []string) {
	pub, sec, err := ed.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("pub:%x\nsec:%x\n", pub, sec)
}

func sign(args []string) {
	m, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}
	sig := ed.Sign(SecKey, m)
	fmt.Printf("%x\n", sig)
}

func verify(args []string) {
	if len(args) < 1 {
		log.Fatal("crap")
	}

	sig, err := hex.DecodeString(args[1])
	if err != nil {
		log.Fatal(err)
	}

	m, err := ioutil.ReadAll(os.Stdin)

	if ed.Verify(PubKey, m, sig) {
		fmt.Println("good")
	} else {
		fmt.Println("bad")
	}
}
