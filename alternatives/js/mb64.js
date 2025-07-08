import crypto from "crypto";
import fs from "fs";

let gcm = null;
let mbEncoding = null;
let bypass = false;

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

function SetEncoding(key) {
  if (key === "") {
    throw new Error("key cannot be empty");
  }

  setGCM(key);
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

function setGCM(basekey) {
  const key = generateKey(basekey);
  gcm = { key };
}

function generateKey(input) {
  return crypto.createHash("sha256").update(input, "utf8").digest();
}

function encrypt(data) {
  if (bypass) {
    return data;
  }

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", gcm.key, iv);

  let encrypted = cipher.update(data);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const authTag = cipher.getAuthTag();

  return Buffer.concat([iv, authTag, encrypted]);
}

function decrypt(data) {
  if (bypass) {
    return data;
  }

  if (data.length < 28) {
    // 12 (IV) + 16 (auth tag) minimum
    throw new Error("ciphertext too short");
  }

  const iv = data.slice(0, 12);
  const authTag = data.slice(12, 28);
  const encrypted = data.slice(28);

  const decipher = crypto.createDecipheriv("aes-256-gcm", gcm.key, iv);
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

function reverse(s) {
  return s.split("").reverse().join("");
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

function shuffleStr(str, numbers) {
  let res = str;
  for (const number of numbers) {
    let _res = "";
    let _str = res;
    while (_str.length > 0) {
      const powResult = (number + _str.length) * Math.abs(number - _str.length);
      const index = powResult % _str.length;
      _res += _str[index];
      _str = _str.slice(0, index) + _str.slice(index + 1);
    }
    _res = reverse(_res);
    res = _res;
  }
  return res;
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
