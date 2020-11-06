// +build ed2curve25519test

package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"

	"github.com/jorrizza/ed2curve25519"
	"golang.org/x/crypto/nacl/box"
)

func main() {
	aliceEd25519Seed := make([]byte, ed25519.SeedSize)
	bobEd25519Seed := make([]byte, ed25519.SeedSize)

	f, err := os.Open("../key_alice")
	if err != nil {
		panic(err)
	}
	if _, err := f.Read(aliceEd25519Seed); err != nil {
		panic(err)
	}
	if err := f.Close(); err != nil {
		panic(err)
	}

	f, err = os.Open("../key_bob")
	if err != nil {
		panic(err)
	}
	if _, err := f.Read(bobEd25519Seed); err != nil {
		panic(err)
	}
	if err := f.Close(); err != nil {
		panic(err)
	}

	ed25519PrivateKey := ed25519.NewKeyFromSeed(aliceEd25519Seed)
	ed25519PublicKey := ed25519PrivateKey.Public().(ed25519.PublicKey)

	fmt.Printf("Ed25519\nprivate: %x\npublic: %x\n", ed25519PrivateKey.Seed(), ed25519PublicKey)

	curve25519PrivateKey := ed2curve25519.Ed25519PrivateKeyToCurve25519(ed25519PrivateKey)
	curve25519PublicKey := ed2curve25519.Ed25519PublicKeyToCurve25519(ed25519PublicKey)

	fmt.Printf("Curve25519\nprivate: %x\npublic: %x\n", curve25519PrivateKey, curve25519PublicKey)

	fmt.Println("NaCl")

	alicePrivateKey, alicePublicKey := new([32]byte), new([32]byte)
	bobPrivateKey, bobPublicKey := new([32]byte), new([32]byte)

	copy(alicePrivateKey[:], curve25519PrivateKey)
	copy(alicePublicKey[:], curve25519PublicKey)

	ed25519PrivateKey = ed25519.NewKeyFromSeed(bobEd25519Seed)
	ed25519PublicKey = ed25519PrivateKey.Public().(ed25519.PublicKey)
	curve25519PrivateKey = ed2curve25519.Ed25519PrivateKeyToCurve25519(ed25519PrivateKey)
	curve25519PublicKey = ed2curve25519.Ed25519PublicKeyToCurve25519(ed25519PublicKey)

	copy(bobPrivateKey[:], curve25519PrivateKey)
	copy(bobPublicKey[:], curve25519PublicKey)

	message := []byte("kill all humans!")
	nonce := new([24]byte)

	f, err = os.Open("../nonce")
	if err != nil {
		panic(err)
	}
	if _, err := f.Read(nonce[:]); err != nil {
		panic(err)
	}
	if err := f.Close(); err != nil {
		panic(err)
	}

	encrypted := box.Seal(nonce[:], message, nonce, bobPublicKey, alicePrivateKey)

	fmt.Printf("Encrypted: %x\n", encrypted)

	decrypted, ok := box.Open(nil, encrypted[24:], nonce, alicePublicKey, bobPrivateKey)
	if !ok {
		panic(errors.New("Could not decrypt message"))
	}

	fmt.Printf("Decrypted: %s\n", decrypted)
}
