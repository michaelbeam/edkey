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

// create a new random ed25519 keypair
func create(args []string) {
	pub, sec, err := ed.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("pub:%x\nsec:%x\n", pub, sec)
}

// sign a message from STDIN using the specified keyfile
func sign(args []string) {
	if len(args) < 2 {
		log.Fatal("Usage: edkey sign KEYFILE")
	}

	// Read the secret key from the file specified on the command line
	seckey := func() ed.PrivateKey {
		f, err := os.Open(args[1])
		if err != nil {
			log.Fatal(err)
		}
		b, err := ioutil.ReadAll(f)
		if err != nil {
			log.Fatal(err)
		}

		// Only read the first 64 hex encoded bytes from the keyfile, ignoring
		// any subsequent characters.
		k := make([]byte, ed.PrivateKeySize)
		if i, err := hex.Decode(k, b[:2*ed.PrivateKeySize]); err != nil {
			log.Fatal(err)
		} else if i < ed.PrivateKeySize {
			log.Fatal("keyfile is the wrong length")
		}
		return k
	}()

	// Read the message to be signed from STDIN.
	m, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}

	// Return the signature of the message.
	sig := ed.Sign(seckey, m)
	fmt.Printf("%x\n", sig)
}

// verify that a message signature matches the message and the public key.
func verify(args []string) {
	if len(args) < 3 {
		log.Fatal("Usage: edkey verify SIGNATURE KEYFILE")
	}

	// Decode the hex encoded signature from the command line.
	sig, err := hex.DecodeString(args[1])
	if err != nil {
		log.Fatal(err)
	}

	// Read the public key from the file specified on the command line.
	pubkey := func() ed.PublicKey {
		f, err := os.Open(args[2])
		if err != nil {
			log.Fatal(err)
		}
		b, err := ioutil.ReadAll(f)
		if err != nil {
			log.Fatal(err)
		}

		// Only read the first 32 hex encoded bytes from the keyfile, ignoring
		// any subsequent characters.
		k := make([]byte, ed.PublicKeySize)
		if i, err := hex.Decode(k, b[:2*ed.PublicKeySize]); err != nil {
			log.Fatal(err)
		} else if i < ed.PublicKeySize {
			log.Fatal("keyfile is the wrong length")
		}
		return k
	}()

	// Read the message from STDIN.
	m, err := ioutil.ReadAll(os.Stdin)

	// Verify that the signature and the message match with the public key.
	if ed.Verify(pubkey, m, sig) {
		fmt.Println("good")
	} else {
		fmt.Println("bad")
	}
}
