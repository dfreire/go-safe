package main

import (
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
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("No file given.")
	}
	root := filepath.Clean(os.Args[1])

	password := promptPassword("Password")
	if password != promptPassword("Repeat") {
		log.Fatal("Passwords do not match.")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	hasher := sha256.New()
	hasher.Write(hash)
	key := hasher.Sum(nil)

	for _, file := range listFiles(root) {
		log.Println(file)
		encryptFile(key, file)
	}
}

func listFiles(root string) []string {
	files := []string{}
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		log.Println(path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if info.Name()[0:1] == "." {
			return nil
		}
		if filepath.Ext(path) == ".aes" {
			return nil
		}
		log.Println(path, "OK")
		files = append(files, path)
		return nil
	}); err != nil {
		panic(err)
	}
	return files
}

func promptPassword(message string) string {
	password, err := prompt.Password(message)
	if err != nil {
		panic(err)
	}
	return password

}

func encryptFile(key []byte, clearfile string) {

	encryptedfile := strings.Join([]string{clearfile, "aes"}, ".")

	cleartext, err := ioutil.ReadFile(clearfile)
	if err != nil {
		log.Fatal(err)
	}

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
