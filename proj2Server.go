package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "modernc.org/sqlite"
)


func main() {
	var err error
	db, err = sql.Open("sqlite", "totally_not_my_privateKeys.db")
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}
	defer db.Close()

	//Create table 
	createTableIfNotExists(db)

	genKeys()
	http.HandleFunc("/.well-known/jwks.json", JWKSHandler)
	http.HandleFunc("/auth", AuthHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

var (
	goodPrivKey    *rsa.PrivateKey
	expiredPrivKey *rsa.PrivateKey
	db 			   *sql.DB
)

//Function to create table
func createTableIfNotExists(db *sql.DB) {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)`)
	if err != nil {
		log.Fatalf("Error creating table: %v", err)
	}
}

//Function to generate keys
func genKeys() {
    var err error
    goodPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        log.Fatalf("Error generating RSA keys: %v", err)
    }

    expiredPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        log.Fatalf("Error generating expired RSA keys: %v", err)
    }

    // Save the generated keys
    saveKey(goodPrivKey, time.Now().Add(1*time.Hour).Unix())
	saveKey(expiredPrivKey, time.Now().Add(-1*time.Hour).Unix())
}

//Function to save keys
func saveKey(privKey *rsa.PrivateKey, exp int64) {
	privBytes := x509.MarshalPKCS1PrivateKey(privKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})
	_, err := db.Exec("INSERT INTO keys(key, exp) VALUES (?, ?)", keyPEM, exp)
	if err != nil {
		log.Fatalf("Error saving key to database: %v", err)
	}
}

const goodKID = "aRandomKeyID"

//Function to handle /auth port
func AuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var (
		signingKey *rsa.PrivateKey
		keyID      string
		exp        int64
	)

	// Default to the good key
	signingKey = getKey(false)
	keyID = goodKID
	exp = time.Now().Add(1 * time.Hour).Unix()

	// If the expired query parameter is set, use the expired key
	if expired, _ := strconv.ParseBool(r.URL.Query().Get("expired")); expired {
		signingKey = getKey(true)
		keyID = "expiredKeyId"
		exp = time.Now().Add(-1 * time.Hour).Unix()
	}

	// Create the token with the expiry
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"exp": exp,
	})
	token.Header["kid"] = keyID
	// Sign the token with the private key
	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}

	_, _ = w.Write([]byte(signedToken))
}

//Function to retrieve the key
func getKey(isExpired bool) *rsa.PrivateKey {
	var (
		keyBytes []byte
		exp      int64
	)

	query := "SELECT key, exp FROM keys WHERE exp > ?"
	if isExpired {
		query = "SELECT key, exp FROM keys WHERE exp <= ?"
	}

	row := db.QueryRow(query, time.Now().Unix())
	err := row.Scan(&keyBytes, &exp)
	if err != nil {
		log.Fatalf("Error getting key from database: %v", err)
	}

	block, _ := pem.Decode(keyBytes)
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Error parsing private key: %v", err)
	}
	return privKey
}

type (
	JWKS struct {
		Keys []JWK `json:"keys"`
	}
	JWK struct {
		KID       string `json:"kid"`
		Algorithm string `json:"alg"`
		KeyType   string `json:"kty"`
		Use       string `json:"use"`
		N         string `json:"n"`
		E         string `json:"e"`
	}
)

//Function to handle /.well-known/jwks.json endpoint
func JWKSHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	base64URLEncode := func(b *big.Int) string {
		return base64.RawURLEncoding.EncodeToString(b.Bytes())
	}

	rows, err := db.Query("SELECT key, exp FROM keys WHERE exp > ?", time.Now().Unix())
	if err != nil {
		log.Fatalf("Error retrieving keys from database: %v", err)
	}
	defer rows.Close()

	var keys []JWK
	for rows.Next() {
		var keyBytes []byte
		var exp int64
		if err := rows.Scan(&keyBytes, &exp); err != nil {
			log.Fatalf("Error scanning rows: %v", err)
		}

		block, _ := pem.Decode(keyBytes)
		privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			log.Fatalf("Error parsing private key: %v", err)
		}

		publicKey := &privKey.PublicKey

		keys = append(keys, JWK{
			KID:       goodKID,
			Algorithm: "RS256",
			KeyType:   "RSA",
			Use:       "sig",
			N:         base64URLEncode(publicKey.N),
			E:         base64URLEncode(big.NewInt(int64(publicKey.E))),
		})
	}

	resp := JWKS{
		Keys: keys,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}