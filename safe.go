package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"github.com/bowery/prompt"
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

	hash := promptPassword("Password")
	if hash != promptPassword("Repeat") {
		log.Fatal("Passwords do not match.")
	}

	key := []byte(hash)

	for _, file := range listFilesToEncrypt(root) {
		log.Println("Encrypt", file)
		encryptFile(key, file)
	}

	for _, file := range listFilesToDecrypt(root) {
		log.Println("Decrypt", file)
		//decryptFile(key, file)
	}
}

func promptPassword(message string) string {
	password, err := prompt.Password(message)
	if err != nil {
		panic(err)
	}
	hasher := sha256.New()
	hasher.Write([]byte(password))
	return string(hasher.Sum(nil))
}

func listFilesToEncrypt(root string) []string {
	files := []string{}
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
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
		files = append(files, path)
		return nil
	}); err != nil {
		panic(err)
	}
	return files
}

func encryptFile(key []byte, clearfile string) {
	encryptedfile := strings.Join([]string{clearfile, "aes"}, ".")

	cleartext, err := ioutil.ReadFile(clearfile)
	if err != nil {
		log.Fatal(err)
	}

	encryptedtext, err := encryptText(key, cleartext)
	if err != nil {
		log.Fatal(err)
	}

	if err := ioutil.WriteFile(encryptedfile, encryptedtext, 0644); err != nil {
		panic(err)
	}
}

func encryptText(key, text []byte) ([]byte, error) {
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

func listFilesToDecrypt(root string) []string {
	files := []string{}
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
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
			files = append(files, path)
		}
		return nil
	}); err != nil {
		panic(err)
	}
	return files
}

/*
func decryptFile(key []byte, encryptedfile string) {
	cleartext, err := ioutil.ReadFile(clearfile)
	if err != nil {
		log.Fatal(err)
	}

	result, err := decrypt(key, encryptedtext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Decrypted %s\n", result)
}

func decryptText(key, text []byte) ([]byte, error) {
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
*/
