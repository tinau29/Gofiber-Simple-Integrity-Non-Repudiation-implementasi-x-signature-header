package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// Fungsi untuk memuat private key dari file dengan path
func loadPrivateKeyFromFile(filePath string) (*rsa.PrivateKey, error) {
	// Baca isi file private key
	keyBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file at %s: %w", filePath, err)
	}

	// Decode private key dari format PEM
	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("invalid private key PEM format")
	}

	// Parse private key ke objek RSA
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Pastikan kunci adalah tipe RSA
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	return rsaKey, nil
}

// Fungsi untuk membuat tanda tangan
func signString(privateKey *rsa.PrivateKey, stringToSign string) (string, error) {
	hash := sha256.New()
	hash.Write([]byte(stringToSign))
	digest := hash.Sum(nil)

	signature, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, digest)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func main() {
	app := fiber.New()

	privateKeyPath := "/files/rsa/private_key.pem"

	clientID := "exampleClientID"
	timestamp := "2024-12-09T10:00:00Z"
	stringToSign := clientID + "|" + timestamp

	app.Post("/auth-signature", func(c *fiber.Ctx) error {
		// Muat private key
		privateKey, err := loadPrivateKeyFromFile(privateKeyPath)
		if err != nil {
			log.Fatal("Failed to load private key:", err)
		}

		// Buat tanda tangan
		signature, err := signString(privateKey, stringToSign)
		if err != nil {
			log.Fatal("Failed to sign string:", err)
		}

		// Kirim permintaan ke server
		req, err := http.NewRequest("POST", "http://server:3000/verify", nil)
		if err != nil {
			// log.Fatal(err)
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": err.Error(),
			})
		}

		req.Header.Set("X-Client-ID", clientID)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Signature", signature)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()

		// Cetak status respons
		fmt.Println("Response Status:", resp.Status)

		// Cetak semua header respons
		fmt.Println("Response Headers:")
		for key, values := range resp.Header {
			fmt.Printf("%s: %s\n", key, strings.Join(values, ", "))
		}

		// Cetak body respons
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Failed to read response body: " + err.Error(),
			})
		}
		fmt.Println("Response Body:")
		fmt.Println(string(body))
		return c.Status(200).SendString(string(body))
	})

	log.Fatal(app.Listen(":3001"))
}
