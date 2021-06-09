package util

import (
	"math/rand"
	"time"
)

var letters = []rune("abcdefghijklmnopqrstuvwxyz")

func RandomString(length int) string {
	testRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomString := make([]rune, length)
	for i := range randomString {
		randomString[i] = letters[testRand.Intn(len(letters))]
	}
	return string(randomString)
}
