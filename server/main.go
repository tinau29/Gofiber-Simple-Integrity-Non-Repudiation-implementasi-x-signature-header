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

	"github.com/gofiber/fiber/v2"
)

// Fungsi untuk memuat public key dari file
func loadPublicKeyFromFile(filePath string) (*rsa.PublicKey, error) {
	// Baca isi file public key
	keyBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file at %s: %w", filePath, err)
	}

	// Decode public key dari format PEM
	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid public key PEM format")
	}

	// Parse public key ke objek RSA
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Pastikan kunci adalah tipe RSA
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaKey, nil
}

// Fungsi untuk memverifikasi tanda tangan digital
func verifySignature(publicKey *rsa.PublicKey, stringToSign, signatureBase64 string) bool {
	// Decode signature dari base64
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		log.Println("Failed to decode signature:", err)
		return false
	}

	// Buat hash dari stringToSign
	hash := sha256.New()
	hash.Write([]byte(stringToSign))
	digest := hash.Sum(nil)

	// Verifikasi tanda tangan
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest, signature)
	if err != nil {
		log.Println("Verification failed:", err)
		return false
	}
	return true
}

func main() {
	app := fiber.New()

	publicKeyPath := "files/rsa/public_key.pem"

	app.Post("/verify", func(c *fiber.Ctx) error {
		clientID := c.Get("X-Client-ID")
		timestamp := c.Get("X-Timestamp")
		signature := c.Get("X-Signature")

		// Rekonstruksi stringToSign
		stringToSign := clientID + "|" + timestamp

		// Muat public key
		publicKey, err := loadPublicKeyFromFile(publicKeyPath)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"status":  "error",
				"message": err.Error(),
			})
		}

		// Verifikasi tanda tangan
		if verifySignature(publicKey, stringToSign, signature) {
			return c.Status(fiber.StatusOK).JSON(fiber.Map{
				"status":         "success",
				"message":        "Signature is valid!",
				"client_id":      clientID,
				"timestamp":      timestamp,
				"string_to_sign": stringToSign,
			})
		}

		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":         "error",
			"message":        "Invalid signature!",
			"client_id":      clientID,
			"timestamp":      timestamp,
			"string_to_sign": stringToSign,
		})
	})

	log.Fatal(app.Listen(":3000"))
}
