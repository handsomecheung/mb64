import crypto from "crypto";
import { SetEncoding, Encode, Decode } from "../mb64.js";

const b64BaseChars =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function testShuffleStr() {
  console.log("=== Testing ARX shuffleStr Implementation ===\n");

  function generateSha256(input) {
    return crypto.createHash("sha256").update(input, "utf8").digest();
  }

  function genCharMap(chars) {
    const map = {};
    for (let i = 0; i < chars.length; i++) {
      map[chars[i]] = i;
    }
    return map;
  }

  function sum(numbers) {
    return numbers.reduce((total, n) => total + n, 0);
  }

  const baseCharsMap = genCharMap(b64BaseChars);

  function charsToNumbers(chars) {
    const numbers = [];
    for (const c of chars) {
      if (c === "=") {
        numbers.push(sum(numbers) % 64);
      } else {
        numbers.push(baseCharsMap[c]);
      }
    }
    return numbers;
  }

  function quarterRound(a, b, c, d) {
    a = a >>> 0;
    b = b >>> 0;
    c = c >>> 0;
    d = d >>> 0;

    a = (a + b) >>> 0;
    d = (d ^ a) >>> 0;
    d = ((d << 16) | (d >>> 16)) >>> 0;

    c = (c + d) >>> 0;
    b = (b ^ c) >>> 0;
    b = ((b << 12) | (b >>> 20)) >>> 0;

    a = (a + b) >>> 0;
    d = (d ^ a) >>> 0;
    d = ((d << 8) | (d >>> 24)) >>> 0;

    c = (c + d) >>> 0;
    b = (b ^ c) >>> 0;
    b = ((b << 7) | (b >>> 25)) >>> 0;

    return [a, b, c, d];
  }

  function arxPRNG(state, rounds) {
    let [a, b, c, d] = state;

    for (let i = 0; i < rounds; i++) {
      [a, b, c, d] = quarterRound(a, b, c, d);
    }

    state[0] = a;
    state[1] = b;
    state[2] = c;
    state[3] = d;

    return (a ^ b ^ c ^ d) >>> 0;
  }

  function shuffleStr(str, numbers) {
    if (str.length <= 1) {
      return str;
    }

    const chars = str.split("");
    const n = chars.length;

    const state = [0, 0, 0, 0];
    const constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    for (let i = 0; i < 4; i++) {
      if (i < numbers.length) {
        state[i] = numbers[i] >>> 0;
      } else {
        state[i] = constants[i];
      }
    }

    let minRounds = 10;
    if (numbers.length > minRounds) {
      minRounds = numbers.length;
    }

    for (let round = 0; round < minRounds; round++) {
      for (let i = n - 1; i > 0; i--) {
        const randVal = arxPRNG(state, 4);
        const j = randVal % (i + 1);
        [chars[i], chars[j]] = [chars[j], chars[i]];
      }

      if (round < numbers.length) {
        state[round % 4] = (state[round % 4] ^ numbers[round]) >>> 0;
      }
    }

    return chars.join("");
  }

  function shuffleBaseChars(key) {
    const b64 = Buffer.from(key).toString("base64");
    const numbers = charsToNumbers(b64);
    return shuffleStr(b64BaseChars, numbers);
  }

  console.log("Test 1: Base64 alphabet shuffling");
  const key1 = generateSha256("test123");
  const shuffled1 = shuffleBaseChars(key1);
  console.log("Original: ", b64BaseChars);
  console.log("Shuffled: ", shuffled1);
  console.log("Length match:", b64BaseChars.length === shuffled1.length);
  console.log("Is different:", b64BaseChars !== shuffled1);
  console.log();

  console.log("Test 2: Deterministic output");
  const numbers = [123, 456, 789];
  const result1 = shuffleStr(b64BaseChars, numbers);
  const result2 = shuffleStr(b64BaseChars, numbers);
  console.log("Result 1:", result1);
  console.log("Result 2:", result2);
  console.log("Deterministic:", result1 === result2);
  console.log();

  console.log("Test 3: Different seeds");
  const numbers2 = [123, 456, 790];
  const result3 = shuffleStr(b64BaseChars, numbers2);
  console.log("Seed 1 result:", result1);
  console.log("Seed 2 result:", result3);
  console.log("Different results:", result1 !== result3);
  console.log();

  console.log("Test 4: Edge cases");
  console.log("Empty string:", shuffleStr("", [1, 2, 3]) === "");
  console.log("Single char:", shuffleStr("A", [1, 2, 3]) === "A");
  console.log("Two chars:", shuffleStr("AB", [5]).length === 2);
  console.log();

  console.log("Test 5: Character preservation");
  const original = "ABCDEFGHIJKLMNOP";
  const shuffled = shuffleStr(original, [42, 123]);
  const origChars = original.split("").sort().join("");
  const shuffChars = shuffled.split("").sort().join("");
  console.log("Original sorted:", origChars);
  console.log("Shuffled sorted:", shuffChars);
  console.log("All chars preserved:", origChars === shuffChars);
  console.log();
}

function testEncodeDecode() {
  console.log("=== Testing Encode/Decode with ARX ===\n");

  const testKey = "mySecretKey123";
  SetEncoding(testKey);

  const testData = Buffer.from("Hello, World! This is a test message.");
  console.log("Original data:", testData.toString());

  const encoded = Encode(testData);
  console.log("Encoded:", encoded.toString());
  console.log("Encoded length:", encoded.length);

  const decoded = Decode(encoded);
  console.log("Decoded:", decoded.toString());
  console.log("Match:", decoded.toString() === testData.toString());
  console.log();

  const testData2 = Buffer.from(
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
  );
  const encoded2 = Encode(testData2);
  const decoded2 = Decode(encoded2);
  console.log("Test 2 - Original:", testData2.toString());
  console.log("Test 2 - Decoded: ", decoded2.toString());
  console.log(
    "Test 2 - Match:   ",
    decoded2.toString() === testData2.toString(),
  );
}

testShuffleStr();
testEncodeDecode();
console.log("\n✅ All tests completed!");
