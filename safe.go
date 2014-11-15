package main

import (
	"strings"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/bowery/prompt"
	"golang.org/x/crypto/bcrypt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("No file given.")
	}

	clearfile := filepath.Clean(os.Args[1])
	encryptedfile := strings.Join([]string{clearfile, "aes"}, ".")

	cleartext, err := ioutil.ReadFile(clearfile)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Password: ")
	password, err := prompt.Password("Password")
	if err != nil {
		panic(err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}

	hasher := sha256.New()
	hasher.Write(hash)
	key := hasher.Sum(nil)

	fmt.Printf("%s\n", cleartext)

	encryptedtext, err := encrypt(key, cleartext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%0x\n", encryptedtext)

	if err := ioutil.WriteFile(encryptedfile, encryptedtext, 0644); err != nil {
		panic(err)
	}

	result, err := decrypt(key, encryptedtext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", result)
}

func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	encryptedtext := make([]byte, aes.BlockSize+len(b))
	iv := encryptedtext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(encryptedtext[aes.BlockSize:], []byte(b))
	return encryptedtext, nil
}

func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("encryptedtext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}

func openFile() {

}
