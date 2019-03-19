package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

func AuthCode(sec string, ts int64) (string, error) {
	key, err := base32.StdEncoding.DecodeString(sec)
	if err != nil {
		return "", err
	}
	enc := hmac.New(sha1.New, key)
	msg := make([]byte, 8, 8)
	msg[0] = (byte)(ts >> (7 * 8) & 0xff)
	msg[1] = (byte)(ts >> (6 * 8) & 0xff)
	msg[2] = (byte)(ts >> (5 * 8) & 0xff)
	msg[3] = (byte)(ts >> (4 * 8) & 0xff)
	msg[4] = (byte)(ts >> (3 * 8) & 0xff)
	msg[5] = (byte)(ts >> (2 * 8) & 0xff)
	msg[6] = (byte)(ts >> (1 * 8) & 0xff)
	msg[7] = (byte)(ts >> (0 * 8) & 0xff)
	if _, err := enc.Write(msg); err != nil {
		return "", err
	}
	hash := enc.Sum(nil)
	offset := hash[19] & 0x0f
	trunc := hash[offset : offset+4]
	trunc[0] &= 0x7F
	res := new(big.Int).Mod(new(big.Int).SetBytes(trunc), big.NewInt(1000000))
	return fmt.Sprintf("%06d", res), nil
}

func authCodeOrDie(sec string, ts int64) string {
	str, e := AuthCode(sec, ts)
	if e != nil {
		log.Fatal(e)
	}
	return str
}

func main() {
	token := os.Args[1]
	code := authCodeOrDie(token, time.Now().Unix() / 30)
	fmt.Print(code)
}
