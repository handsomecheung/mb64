import crypto from "crypto";
import fs from "fs";

let mbEncoding = null;
let bypass = false;
let baseKey = "";

class LRUCache {
  constructor(capacity) {
    this.capacity = capacity;
    this.cache = new Map();
  }

  get(key) {
    if (!this.cache.has(key)) {
      return null;
    }
    const value = this.cache.get(key);
    this.cache.delete(key);
    this.cache.set(key, value);
    return value;
  }

  put(key, value) {
    if (this.cache.has(key)) {
      this.cache.delete(key);
    } else if (this.cache.size >= this.capacity) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    this.cache.set(key, value);
  }
}

const sha256Cache = new LRUCache(100);
const gcmCache = new LRUCache(10);

const b64BaseChars =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const baseCharsMap = genCharMap(b64BaseChars);

function Bypass() {
  bypass = true;
  mbEncoding = {
    encode: (data) => Buffer.from(data).toString("base64"),
    decode: (data) => Buffer.from(data, "base64"),
  };
}

function SetEncoding(basekey) {
  if (basekey === "") {
    throw new Error("key cannot be empty");
  }

  baseKey = basekey;
  const key = generateKeyB64(basekey);
  mbEncoding = createCustomBase64Encoding(shuffleBaseChars(key));
  bypass = false;
}

function Encode(data) {
  const encrypted = encrypt(data);
  return Buffer.from(mbEncoding.encode(encrypted));
}

function Decode(data) {
  const decoded = mbEncoding.decode(data.toString().trim());
  return decrypt(decoded);
}

function RenderInFile(key, filepath, output) {
  SetEncoding(key);
  const fileContent = fs.readFileSync(filepath);
  const encoded = Encode(fileContent);
  fs.writeFileSync(output, encoded);
}

function RenderOutFile(key, filepath, output) {
  SetEncoding(key);
  const fileContent = fs.readFileSync(filepath);
  const decoded = Decode(fileContent);
  fs.writeFileSync(output, decoded);
}

function generateSha256(input) {
  const cached = sha256Cache.get(input);
  if (cached) {
    return cached;
  }

  const hash = crypto.createHash("sha256").update(input, "utf8").digest();

  sha256Cache.put(input, hash);

  return hash;
}

function generateKeyB64(input) {
  return generateSha256(input);
}

function generateKeyGCM(input) {
  const date = getCurrentDate();
  return generateSha256(`${input}${date}`);
}

function getCurrentDate() {
  const today = new Date();
  const year = today.getFullYear();
  const month = String(today.getMonth() + 1).padStart(2, "0");
  const day = String(today.getDate()).padStart(2, "0");
  return `${year}${month}${day}`;
}

function createGCM(key) {
  const cacheKey = key.toString("hex");

  const cached = gcmCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  gcmCache.put(cacheKey, key);

  return key;
}

function encrypt(data) {
  if (bypass) {
    return data;
  }

  const key = generateKeyGCM(baseKey);
  const cachedKey = createGCM(key);

  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", cachedKey, nonce);

  let encrypted = cipher.update(data);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Match Go's gcm.Seal format: nonce + encrypted + authTag
  return Buffer.concat([nonce, encrypted, authTag]);
}

function decrypt(data) {
  if (bypass) {
    return data;
  }

  if (data.length < 28) {
    // 12 (nonce) + 16 (auth tag) minimum
    throw new Error("ciphertext too short");
  }

  const key = generateKeyGCM(baseKey);
  const cachedKey = createGCM(key);

  // Match Go's gcm.Open format: nonce + encrypted + authTag
  const nonce = data.slice(0, 12);
  const encrypted = data.slice(12, -16);
  const authTag = data.slice(-16);

  const decipher = crypto.createDecipheriv("aes-256-gcm", cachedKey, nonce);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  return decrypted;
}

function shuffleBaseChars(key) {
  const b64 = Buffer.from(key).toString("base64");
  const numbers = charsToNumbers(b64);
  return shuffleStr(b64BaseChars, numbers);
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

function createCustomBase64Encoding(alphabet) {
  const encode = (data) => {
    let result = "";
    let i = 0;

    while (i < data.length) {
      const a = data[i++];
      const b = i < data.length ? data[i++] : 0;
      const c = i < data.length ? data[i++] : 0;

      const combined = (a << 16) | (b << 8) | c;

      result += alphabet[(combined >> 18) & 63];
      result += alphabet[(combined >> 12) & 63];
      result += alphabet[(combined >> 6) & 63];
      result += alphabet[combined & 63];
    }

    const padding = data.length % 3;
    if (padding === 1) {
      result = result.slice(0, -2) + "==";
    } else if (padding === 2) {
      result = result.slice(0, -1) + "=";
    }

    return result;
  };

  const decode = (str) => {
    const reverseMap = {};
    for (let i = 0; i < alphabet.length; i++) {
      reverseMap[alphabet[i]] = i;
    }

    str = str.replace(/=+$/, "");
    const result = [];
    let i = 0;

    while (i < str.length) {
      const a = reverseMap[str[i++]] || 0;
      const b = reverseMap[str[i++]] || 0;
      const c = reverseMap[str[i++]] || 0;
      const d = reverseMap[str[i++]] || 0;

      const combined = (a << 18) | (b << 12) | (c << 6) | d;

      result.push((combined >> 16) & 255);
      if (i - 2 < str.length) result.push((combined >> 8) & 255);
      if (i - 1 < str.length) result.push(combined & 255);
    }

    return Buffer.from(result);
  };

  return { encode, decode };
}

export { Bypass, SetEncoding, Encode, Decode, RenderInFile, RenderOutFile };
