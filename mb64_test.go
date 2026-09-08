package mb64

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func genRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%|'\\()@[]{};+:*,<>.\"_"

	rand.New(rand.NewSource(time.Now().UnixNano()))

	b := make([]byte, length)

	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}

	return string(b)
}

func checkErr(t *testing.T, err error) {
	if err != nil {
		t.Errorf("error: %s", err.Error())
	}
}

func checkCorrectness(t *testing.T, chars string) {
	if len(chars) != len(b64BaseChars) {
		t.Errorf("length mismatch: got %d, want %d", len(chars), len(b64BaseChars))
		return
	}

	charMap := make(map[rune]bool)
	baseCharsMap := make(map[rune]bool)

	for _, c := range b64BaseChars {
		baseCharsMap[c] = true
	}

	for _, c := range chars {
		if !baseCharsMap[c] {
			t.Errorf("invalid character found: %c", c)
			return
		}

		if charMap[c] {
			t.Errorf("duplicate character found: %c", c)
			return
		}

		charMap[c] = true
	}
}

func checkContinuity(t *testing.T, chars string) {
	count := 0
	lastChar := rune(0)

	for i, c := range chars {
		if i > 0 && c == lastChar+1 {
			count++
			if count > 4 {
				t.Errorf("found more than 4 consecutive characters: %s", chars[i-4:i+1])
				return
			}
		} else {
			count = 1
		}
		lastChar = c
	}
}

func testWithoutSetEncoding(t *testing.T) {
	content := "hello world"

	encoded, err_e := Encode([]byte(content))
	checkErr(t, err_e)

	bytes, err_d := Decode(encoded)
	checkErr(t, err_d)

	content1 := string(bytes)
	if content1 != content {
		t.Errorf("`%s` != `%s`", content1, content)
	}

	bytes_b64, err_b64 := base64.StdEncoding.DecodeString(string(encoded))
	checkErr(t, err_b64)
	string_b64 := string(bytes_b64)
	if string_b64 != content {
		t.Errorf("base64 content `%s` != `%s`", string_b64, content)
	}
}

func TestBypass(t *testing.T) {
	Bypass()
	testWithoutSetEncoding(t)
}

func TestSetEncodingAndBypass(t *testing.T) {
	err := SetEncoding("notuse")
	checkErr(t, err)
	Bypass()
	testWithoutSetEncoding(t)
}

func TestBypassAndSetEncoding(t *testing.T) {
	Bypass()
	TestEncodeAndDecode(t)
}

func TestEncodeAndDecode(t *testing.T) {
	key := "abcdefg"
	err_s := SetEncoding(key)
	checkErr(t, err_s)

	content := "hello world"

	encoded, err_e := Encode([]byte(content))
	checkErr(t, err_e)

	bytes, err_d := Decode(encoded)
	checkErr(t, err_d)

	content1 := string(bytes)
	if content1 != content {
		t.Errorf("`%s` != `%s`", content1, content)
	}
}

func TestEncodeAndDecodeCJK(t *testing.T) {
	key := "abcdefg"
	err_s := SetEncoding(key)
	checkErr(t, err_s)

	content := "こんにちは、世界。GO"

	encoded, err_e := Encode([]byte(content))
	checkErr(t, err_e)

	bytes, err_d := Decode(encoded)
	checkErr(t, err_d)

	content1 := string(bytes)
	if content1 != content {
		t.Errorf("`%s` != `%s`", content1, content)
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	key := "abcdefg"
	err_s := SetEncoding(key)
	checkErr(t, err_s)

	content := "hello world"

	encrypted1, err_e1 := encrypt([]byte(content))
	checkErr(t, err_e1)

	bytes, err_d := decrypt(encrypted1)
	checkErr(t, err_d)

	content1 := string(bytes)
	if content1 != content {
		t.Errorf("`%s` != `%s`", content1, content)
	}

	encrypted2, err_e2 := encrypt([]byte(content))
	checkErr(t, err_e2)
	if string(encrypted1) == string(encrypted2) {
		t.Errorf("`%s` != `%s`", string(encrypted1), string(encrypted2))
	}
}

func TestEncodeAndDecodeWithTTL(t *testing.T) {
	key := "my-secret-key-123"
	err := SetEncoding(key)
	checkErr(t, err)

	content := "secure message"

	// 1. Valid TTL
	encoded, err := Encode([]byte(content))
	checkErr(t, err)

	decoded, err := DecodeWithTTL(encoded, 10*time.Second)
	checkErr(t, err)
	if string(decoded) != content {
		t.Errorf("got %s, want %s", string(decoded), content)
	}

	// 2. Decode with TTL = 0 (no expiration check)
	decodedNoTTL, err := Decode(encoded)
	checkErr(t, err)
	if string(decodedNoTTL) != content {
		t.Errorf("got %s, want %s", string(decodedNoTTL), content)
	}
}

func TestTTL_Expired(t *testing.T) {
	key := "my-secret-key-123"
	err := SetEncoding(key)
	checkErr(t, err)

	content := "expired message"

	// Encoded 10 seconds in the past
	pastTime := time.Now().Add(-10 * time.Second)
	encoded, err := EncodeWithTime([]byte(content), pastTime)
	checkErr(t, err)

	// TTL of 5 seconds should fail
	_, err = DecodeWithTTL(encoded, 5*time.Second)
	if !errors.Is(err, ErrExpired) {
		t.Errorf("expected ErrExpired, got %v", err)
	}

	// TTL of 15 seconds should pass
	decoded, err := DecodeWithTTL(encoded, 15*time.Second)
	checkErr(t, err)
	if string(decoded) != content {
		t.Errorf("got %s, want %s", string(decoded), content)
	}
}

func TestTTL_ClockSkew(t *testing.T) {
	key := "my-secret-key-123"
	err := SetEncoding(key)
	checkErr(t, err)

	content := "future message"

	// Encoded far in the future (beyond clock skew limit)
	futureTime := time.Now().Add(2 * time.Minute)
	encoded, err := EncodeWithTime([]byte(content), futureTime)
	checkErr(t, err)

	_, err = DecodeWithTTL(encoded, 5*time.Minute)
	if !errors.Is(err, ErrInvalidTimestamp) {
		t.Errorf("expected ErrInvalidTimestamp, got %v", err)
	}
}

func TestDateIndependence(t *testing.T) {
	// Verify that key derivation does not depend on the current calendar date
	key := "cross-date-key"
	err := SetEncoding(key)
	checkErr(t, err)

	content := "persists across days"

	// Encoded yesterday
	yesterday := time.Now().Add(-24 * time.Hour)
	encoded, err := EncodeWithTime([]byte(content), yesterday)
	checkErr(t, err)

	// Without TTL check (or with large TTL), it should decode successfully
	decoded, err := Decode(encoded)
	checkErr(t, err)
	if string(decoded) != content {
		t.Errorf("got %s, want %s", string(decoded), content)
	}
}

func TestExtractTimestampFromCiphertext(t *testing.T) {
	key := "verify-timestamp-key"
	err := SetEncoding(key)
	checkErr(t, err)

	content := "Hello world timestamp test"
	expectedTime := time.Date(2026, 9, 8, 14, 0, 0, 0, time.UTC)

	// 1. Encode with a specific known timestamp
	encoded, err := EncodeWithTime([]byte(content), expectedTime)
	checkErr(t, err)

	// 2. Extract prefix (first 8 Base64 characters)
	if len(encoded) < 8 {
		t.Fatalf("encoded string too short: %s", string(encoded))
	}
	prefix := encoded[:8]

	// 3. Decode the 8 Base64 characters into binary (6 bytes)
	var headerBuf [6]byte
	n, err := mbEncoding.Decode(headerBuf[:], prefix)
	checkErr(t, err)
	if n < 4 {
		t.Fatalf("decoded header too short, got %d bytes, want at least 4", n)
	}

	// 4. Extract 4-byte uint32 timestamp
	tsUint := binary.BigEndian.Uint32(headerBuf[:4])
	extractedTime := time.Unix(int64(tsUint), 0).UTC()

	// 5. Compare with expected timestamp
	if extractedTime.Unix() != expectedTime.Unix() {
		t.Errorf("timestamp mismatch: got %v (unix: %d), want %v (unix: %d)",
			extractedTime, extractedTime.Unix(), expectedTime, expectedTime.Unix())
	}

	// 6. Verify formatted time format (e.g. YYYY-MM-DD HH:MM:SS)
	formattedTime := extractedTime.Format("2006-01-02 15:04:05")
	if formattedTime != "2026-09-08 14:00:00" {
		t.Errorf("formatted time mismatch: got %s, want 2026-09-08 14:00:00", formattedTime)
	}

	t.Logf("Successfully extracted timestamp: %s (unix: %d) from ciphertext prefix: %s",
	formattedTime, tsUint, string(prefix))
}

func TestShuffle(t *testing.T) {
	basekeys := []string{" ", "a", "abcd1234#$%"}
	for _, basekey := range basekeys {
		key := generateKeyB64(basekey)
		chars := shuffleBaseChars(key)
		fmt.Println(chars)
	}
}

func TestIdempotence(t *testing.T) {
	for i := range make([]int, 100) {
		basekey := genRandomString(i + 1)
		fmt.Println("TestIdempotence with basekey: ", basekey)

		key := generateKeyB64(basekey)
		chars := shuffleBaseChars(key)

		for _ = range make([]int, 200) {
			chars1 := shuffleBaseChars(key)
			if chars1 != chars {
				t.Errorf("`%s` != `%s`", chars1, chars)
			}
		}
	}
}

func TestCorrectness(t *testing.T) {
	for i := range [100]struct{}{} {
		basekey := genRandomString(i + 1)
		fmt.Println("TestCorrectness with basekey: ", basekey)

		for range [200]struct{}{} {
			key := generateKeyB64(basekey)
			chars := shuffleBaseChars(key)
			checkCorrectness(t, chars)
		}
	}
}

func TestContinuity(t *testing.T) {
	for i := range [100]struct{}{} {
		basekey := genRandomString(i + 1)
		fmt.Println("TestContinuity with basekey: ", basekey)

		for range [200]struct{}{} {
			key := generateKeyB64(basekey)
			chars := shuffleBaseChars(key)
			checkContinuity(t, chars)
		}
	}
}

func TestShuffleStrARX(t *testing.T) {
	testCases := []struct {
		name    string
		input   string
		numbers []int
	}{
		{
			name:    "Base64 alphabet",
			input:   b64BaseChars,
			numbers: []int{1, 2, 3, 4, 5},
		},
		{
			name:    "Short string",
			input:   "ABCDEFGH",
			numbers: []int{42, 123, 456},
		},
		{
			name:    "Single number",
			input:   "0123456789",
			numbers: []int{999},
		},
		{
			name:    "Many rounds",
			input:   "ABCDEFGHIJKLMNOP",
			numbers: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			shuffled := shuffleStr(tc.input, tc.numbers)

			if len(shuffled) != len(tc.input) {
				t.Errorf("Length mismatch: got %d, want %d", len(shuffled), len(tc.input))
			}

			inputRunes := []rune(tc.input)
			shuffledRunes := []rune(shuffled)
			charCount := make(map[rune]int)

			for _, r := range inputRunes {
				charCount[r]++
			}
			for _, r := range shuffledRunes {
				charCount[r]--
			}
			for char, count := range charCount {
				if count != 0 {
					t.Errorf("Character count mismatch for '%c': %d", char, count)
				}
			}

			if shuffled == tc.input && len(tc.input) > 1 {
				t.Errorf("String not shuffled: %s", shuffled)
			}

			t.Logf("Input:    %s", tc.input)
			t.Logf("Shuffled: %s", shuffled)
		})
	}
}

func TestShuffleStrDeterministic(t *testing.T) {
	input := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	numbers := []int{123, 456, 789}

	// Should produce same result with same inputs
	result1 := shuffleStr(input, numbers)
	result2 := shuffleStr(input, numbers)

	if result1 != result2 {
		t.Errorf("Non-deterministic results:\n%s\n%s", result1, result2)
	}

	// Different numbers should produce different results
	numbers2 := []int{123, 456, 790}
	result3 := shuffleStr(input, numbers2)

	if result1 == result3 {
		t.Errorf("Different seeds produced same result")
	}

	t.Logf("Seed 1 result: %s", result1)
	t.Logf("Seed 2 result: %s", result3)
}

func TestShuffleStrEdgeCases(t *testing.T) {
	if result := shuffleStr("", []int{1, 2, 3}); result != "" {
		t.Errorf("Empty string: got %s, want empty", result)
	}

	// Single character
	if result := shuffleStr("A", []int{1, 2, 3}); result != "A" {
		t.Errorf("Single char: got %s, want A", result)
	}

	// Empty numbers array
	input := "ABCDEF"
	result := shuffleStr(input, []int{})
	if len(result) != len(input) {
		t.Errorf("Empty numbers: length mismatch")
	}
}

// Benchmark to compare performance
func BenchmarkShuffleStrARX(b *testing.B) {
	input := b64BaseChars
	numbers := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		shuffleStr(input, numbers)
	}
}

// Test 1: Test decrypting ciphertext created 2 minutes past expiration
func TestDecodePastExpirationTimestamp(t *testing.T) {
	key := "past-expiration-key"
	err := SetEncoding(key)
	checkErr(t, err)

	content := "message expired 2 minutes ago"
	ttl := 5 * time.Minute
	// Created 7 minutes ago (2 minutes past the 5-minute TTL)
	pastTime := time.Now().Add(-7 * time.Minute)

	encoded, err := EncodeWithTime([]byte(content), pastTime)
	checkErr(t, err)

	// Case 1a: Decode without TTL check should succeed
	decoded, err := Decode(encoded)
	checkErr(t, err)
	if string(decoded) != content {
		t.Errorf("got %s, want %s", string(decoded), content)
	}

	// Case 1b: Decode with TTL check should fail with ErrExpired
	_, err = DecodeWithTTL(encoded, ttl)
	if !errors.Is(err, ErrExpired) {
		t.Errorf("expected ErrExpired, got %v", err)
	}
}

// Test 2: Test decrypting ciphertext created 2 minutes in the future (beyond clock skew)
func TestDecodeFutureTimestamp(t *testing.T) {
	key := "future-timestamp-key"
	err := SetEncoding(key)
	checkErr(t, err)

	content := "message from 2 minutes in the future"
	// Created 2 minutes in the future (exceeds default 60s clock skew)
	futureTime := time.Now().Add(2 * time.Minute)

	encoded, err := EncodeWithTime([]byte(content), futureTime)
	checkErr(t, err)

	// Case 2a: Decode without TTL check should succeed
	decoded, err := Decode(encoded)
	checkErr(t, err)
	if string(decoded) != content {
		t.Errorf("got %s, want %s", string(decoded), content)
	}

	// Case 2b: Decode with TTL check should fail with ErrInvalidTimestamp (future clock skew)
	_, err = DecodeWithTTL(encoded, 5*time.Minute)
	if !errors.Is(err, ErrInvalidTimestamp) {
		t.Errorf("expected ErrInvalidTimestamp, got %v", err)
	}
}

// Test 3: Test ciphertext with invalid timestamp prefix fails to decrypt
func TestDecodeInvalidTimestampPrefix(t *testing.T) {
	key := "invalid-prefix-key"
	err := SetEncoding(key)
	checkErr(t, err)

	testCases := []struct {
		name  string
		input []byte
	}{
		{
			name:  "Too short (less than 8 chars)",
			input: []byte("abc"),
		},
		{
			name:  "Non-Base64 characters in prefix",
			input: []byte("!@#$%^&*()_+1234567890abcdefghijklmnopqrstuvwxyz"),
		},
		{
			name:  "Base64 characters in prefix",
			input: []byte("Qm9ybiBpbiBIYW1idXJnIHRvIGEgbXVzaWNhbCBmYW1pbHksIEJyYWhtcyBjb21wb3NlZCBhbmQgcGVyZm9ybWVkIGxvY2FsbHkgaW4gaGlzIHlvdXRoIGJlZm9yZSB0b3VyaW5nIENlbnRyYWwgRXVyb3BlIGFzIGEgcGlhbmlzdCwgcHJlbWllcmluZyBoaXMgb3duIHdvcmtzIGFuZCBtZWV0aW5nIEZyYW56IExpc3p0IGluIFdlaW1hci4K"),
		},
		{
			name:  "Normal plaintext string",
			input: []byte("Hello, this is a plain text message not encrypted by mb64!"),
		},
		{
			name:  "Corrupted timestamp prefix",
			input: []byte("@@@@@@@@1234567890abcdefghijklmnopqrstuvwxyz"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(tc.input)
			if err == nil {
				t.Errorf("[%s] expected decode error for invalid input, got nil", tc.name)
			}

			_, errTTL := DecodeWithTTL(tc.input, 5*time.Minute)
			if errTTL == nil {
				t.Errorf("[%s] expected DecodeWithTTL error for invalid input, got nil", tc.name)
			}
		})
	}
}

// Test 4: Iterate all uppercase and lowercase single letters and verify ciphertext length
func TestSingleCharacterCiphertextLength(t *testing.T) {
	key := "single-char-length-key"
	err := SetEncoding(key)
	checkErr(t, err)

	// Expected length for 1-byte plaintext:
	// Binary length = Nonce(12B) + Plaintext(1B) + AuthTag(16B) = 29 bytes.
	// Base64 encoded length = ceil(29/3) * 4 = 10 * 4 = 40 characters (with 1 '=' padding).
	const expectedLength = 40

	var testChars []byte
	for c := byte('A'); c <= byte('Z'); c++ {
		testChars = append(testChars, c)
	}
	for c := byte('a'); c <= byte('z'); c++ {
		testChars = append(testChars, c)
	}

	for _, ch := range testChars {
		charStr := string([]byte{ch})
		encoded, err := Encode([]byte(charStr))
		checkErr(t, err)

		// Verify encoded length is exactly 40 chars
		if len(encoded) != expectedLength {
			t.Errorf("character '%c': expected ciphertext length %d, got %d (ciphertext: %s)",
				ch, expectedLength, len(encoded), string(encoded))
		}

		// Verify decode roundtrip
		decoded, err := Decode(encoded)
		checkErr(t, err)
		if string(decoded) != charStr {
			t.Errorf("character '%c': expected decrypted %s, got %s", ch, charStr, string(decoded))
		}
	}
}
