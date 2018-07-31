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

func main() {
	c := cli.New()
	c.HelpMsg = "edkey create|sign|verify"
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
	if len(args) < 2 {
		log.Fatal("Usage: edkey sign KEYFILE")
	}

	seckey := func() ed.PrivateKey {
		f, err := os.Open(args[1])
		if err != nil {
			log.Fatal(err)
		}
		b, err := ioutil.ReadAll(f)
		if err != nil {
			log.Fatal(err)
		}

		k := make([]byte, 64)
		if i, err := hex.Decode(k, b[:128]); err != nil {
			log.Fatal(err)
		} else if i < 64 {
			log.Fatal("keyfile is the wrong length")
		}
		return k
	}()

	m, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}

	sig := ed.Sign(seckey, m)
	fmt.Printf("%x\n", sig)
}

func verify(args []string) {
	if len(args) < 3 {
		log.Fatal("Usage: edkey verify SIGNATURE KEYFILE")
	}

	sig, err := hex.DecodeString(args[1])
	if err != nil {
		log.Fatal(err)
	}

	pubkey := func() ed.PublicKey {
		f, err := os.Open(args[2])
		if err != nil {
			log.Fatal(err)
		}
		b, err := ioutil.ReadAll(f)
		if err != nil {
			log.Fatal(err)
		}

		k := make([]byte, 32)
		if i, err := hex.Decode(k, b[:64]); err != nil {
			log.Fatal(err)
		} else if i < 32 {
			log.Fatal("keyfile is the wrong length")
		}
		return k
	}()

	m, err := ioutil.ReadAll(os.Stdin)

	if ed.Verify(pubkey, m, sig) {
		fmt.Println("good")
	} else {
		fmt.Println("bad")
	}
}
