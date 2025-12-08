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

// quarterRound performs a ChaCha20-inspired ARX (Add-Rotate-XOR) operation
// on four 32-bit unsigned integers to provide strong diffusion
func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = (d << 16) | (d >> 16)

	c += d
	b ^= c
	b = (b << 12) | (b >> 20)

	a += b
	d ^= a
	d = (d << 8) | (d >> 24)

	c += d
	b ^= c
	b = (b << 7) | (b >> 25)

	return a, b, c, d
}

// arxPRNG generates pseudo-random numbers using ARX operations
// Similar to ChaCha20's core but simplified for shuffling
func arxPRNG(state *[4]uint32, rounds int) uint32 {
	a, b, c, d := state[0], state[1], state[2], state[3]

	for i := 0; i < rounds; i++ {
		a, b, c, d = quarterRound(a, b, c, d)
	}

	state[0] = a
	state[1] = b
	state[2] = c
	state[3] = d

	return a ^ b ^ c ^ d
}

func shuffleStr(str string, numbers []int) string {
	if len(str) <= 1 {
		return str
	}

	runes := []rune(str)
	n := len(runes)

	var state [4]uint32
	for i := 0; i < 4; i++ {
		if i < len(numbers) {
			state[i] = uint32(numbers[i])
		} else {
			// Use constants from ChaCha20 initial state
			constants := [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}
			state[i] = constants[i]
		}
	}

	minRounds := 10
	if len(numbers) > minRounds {
		minRounds = len(numbers)
	}

	for round := 0; round < minRounds; round++ {
		for i := n - 1; i > 0; i-- {
			randVal := arxPRNG(&state, 4) // 4 quarter-rounds per index
			j := int(randVal % uint32(i+1))

			runes[i], runes[j] = runes[j], runes[i]
		}

		if round < len(numbers) {
			state[round%4] ^= uint32(numbers[round])
		}
	}

	return string(runes)
}
