package mb64

import (
	"encoding/base64"
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
