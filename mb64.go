package mb64

import (
	"container/list"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strings" // New import
	"sync"
	"time"
)

var mu sync.RWMutex
var gcm cipher.AEAD
var mbEncoding *base64.Encoding
var bypass = false
var baseKey string

type lruCache struct {
	mu       sync.RWMutex
	capacity int
	cache    map[string]*list.Element
	lruList  *list.List
}

type cacheEntry struct {
	key   string
	value interface{}
}

func newLRUCache(capacity int) *lruCache {
	return &lruCache{
		capacity: capacity,
		cache:    make(map[string]*list.Element),
		lruList:  list.New(),
	}
}

func (c *lruCache) get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if elem, ok := c.cache[key]; ok {
		c.lruList.MoveToFront(elem)
		return elem.Value.(*cacheEntry).value, true
	}
	return nil, false
}

func (c *lruCache) put(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.cache[key]; ok {
		c.lruList.MoveToFront(elem)
		elem.Value.(*cacheEntry).value = value
		return
	}

	entry := &cacheEntry{key: key, value: value}
	elem := c.lruList.PushFront(entry)
	c.cache[key] = elem

	if c.lruList.Len() > c.capacity {
		oldest := c.lruList.Back()
		if oldest != nil {
			c.lruList.Remove(oldest)
			delete(c.cache, oldest.Value.(*cacheEntry).key)
		}
	}
}

var sha256Cache = newLRUCache(100)
var gcmCache = newLRUCache(100)

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

	baseKey = basekey
	mbEncoding = base64.NewEncoding(shuffleBaseChars(generateKeyB64(basekey)))
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

func newGCM(key []byte) (cipher.AEAD, error) {
	cacheKey := string(key)

	if cached, ok := gcmCache.get(cacheKey); ok {
		return cached.(cipher.AEAD), nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	gcmCache.put(cacheKey, gcm)

	return gcm, nil
}

func generateSha256(input string) []byte {
	if cached, ok := sha256Cache.get(input); ok {
		return cached.([]byte)
	}

	hash := sha256.Sum256([]byte(input))
	result := hash[:]

	sha256Cache.put(input, result)

	return result
}

func generateKeyB64(input string) []byte {
	return generateSha256(input)
}

func generateKeyGCM(input string) []byte {
	date := time.Now().Format("20060102")
	return generateSha256(fmt.Sprintf("%s%s", input, date))
}

func encrypt(data []byte) ([]byte, error) {
	if bypass {
		return data, nil
	}

	err := setGCM(generateKeyGCM(baseKey))
	if err != nil {
		return nil, err
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

	err := setGCM(generateKeyGCM(baseKey))
	if err != nil {
		return nil, err
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
		var b strings.Builder
		runesToShuffle := []rune(res)

		for len(runesToShuffle) > 0 {
			powResult := (number + len(runesToShuffle)) * int(math.Abs(float64(number-len(runesToShuffle))))
			index := powResult % len(runesToShuffle)

			b.WriteRune(runesToShuffle[index])
			runesToShuffle = append(runesToShuffle[:index], runesToShuffle[index+1:]...)
		}
		res = reverse(b.String())
	}
	return res
}
