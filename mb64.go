package mb64

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

var mu sync.RWMutex
var gcm cipher.AEAD
var mbEncoding *base64.Encoding
var bypass = false

func Bypass() {
	mu.Lock()
	defer mu.Unlock()

	bypass = true
	mbEncoding = base64.StdEncoding
}

func SetEncoding(basekey string) error {
	mu.Lock()
	defer mu.Unlock()

	if basekey == "" {
		return errors.New("key cannot be empty")
	}

	key := generateKey(basekey)

	err := setGCM(key)
	if err != nil {
		return err
	}

	mbEncoding = base64.NewEncoding(shuffleBaseChars(key))
	bypass = false

	return nil
}

func Encode(data []byte) ([]byte, error) {
	encrypted, err := encrypt(data)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, mbEncoding.EncodedLen(len(encrypted)))
	mbEncoding.Encode(buf, encrypted)
	return buf, nil
}

func Decode(data []byte) ([]byte, error) {
	dbuf := make([]byte, len(data))
	n, err := mbEncoding.Decode(dbuf, []byte(data))
	if err != nil {
		return nil, err
	}

	decrypted, err := decrypt(dbuf[:n])
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

func setGCM(key []byte) error {
	var err error
	gcm, err = newGCM(key)
	if err != nil {
		return err
	}
	return nil
}

func generateKey(input string) []byte {
	date := "" + time.Now().Format("20060102")
	// TODO remove me
	fmt.Printf("current date: [%s]\n", date)

	// generateKey generates a 32-byte key from any input string.
	// It uses SHA-256 to ensure the output is always 32 bytes.
	// The same input will always produce the same output.
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s%s", input, date)))
	return hash[:]
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func encrypt(data []byte) ([]byte, error) {
	if bypass {
		return data, nil
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decrypt(data []byte) ([]byte, error) {
	if bypass {
		return data, nil
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := data[:gcm.NonceSize()]
	ciphertext := data[gcm.NonceSize():]

	return gcm.Open(nil, nonce, ciphertext, nil)
}

var b64BaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func shuffleBaseChars(key []byte) string {
	b64 := base64.StdEncoding.EncodeToString(key)
	numbers := charsToNumbers(b64)
	return shuffleStr(b64BaseChars, numbers)
}

func genCharMap(chars string) map[rune]int {
	m := make(map[rune]int)
	for i, c := range chars {
		m[c] = i
	}
	return m
}

func sum(numbers []int) int {
	total := 0
	for _, n := range numbers {
		total += n
	}
	return total
}

func reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

var baseCharsMap = genCharMap(b64BaseChars)

func charsToNumbers(chars string) []int {
	numbers := []int{}
	for _, c := range chars {
		if c == '=' {
			numbers = append(numbers, sum(numbers)%64)
		} else {
			numbers = append(numbers, baseCharsMap[c])
		}
	}
	return numbers
}

func shuffleStr(str string, numbers []int) string {
	res := str
	for _, number := range numbers {
		_res := ""
		_str := res
		for len(_str) > 0 {
			powResult := (number + len(_str)) * int(math.Abs(float64(number-len(_str))))
			index := powResult % len(_str)
			_res += string(_str[index])
			_str = _str[:index] + _str[index+1:]
		}
		_res = reverse(_res)
		res = _res
	}
	return res
}
