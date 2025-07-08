import fs from "fs";
import path from "path";
import crypto from "crypto";

import * as mb64 from "../mb64.js";

function genRandomString(length) {
  const charset =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%|'\\()@[]{};+:*,<>.\"_";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += charset[Math.floor(Math.random() * charset.length)];
  }
  return result;
}

function testWithoutSetEncoding(testName) {
  const content = "hello world";
  const encoded = mb64.Encode(Buffer.from(content));
  const decoded = mb64.Decode(encoded);
  const content1 = decoded.toString();

  if (content1 !== content) {
    throw new Error(
      `${testName}: content mismatch: '${content1}' !== '${content}'`,
    );
  }

  const bytes_b64 = Buffer.from(encoded.toString(), "base64");
  const string_b64 = bytes_b64.toString();
  if (string_b64 !== content) {
    throw new Error(
      `${testName}: base64 content mismatch: '${string_b64}' !== '${content}'`,
    );
  }

  console.log(`✓ ${testName} passed`);
}

function testBypass() {
  mb64.Bypass();
  testWithoutSetEncoding("TestBypass");
}

function testSetEncodingAndBypass() {
  mb64.SetEncoding("notuse");
  mb64.Bypass();
  testWithoutSetEncoding("TestSetEncodingAndBypass");
}

function testBypassAndSetEncoding() {
  mb64.Bypass();
  testWithoutSetEncoding("TestBypassAndSetEncoding");
}

function testEncodeAndDecode() {
  const key = "abcdefg";
  mb64.SetEncoding(key);
  const content = "hello world";

  const encoded = mb64.Encode(Buffer.from(content));
  const decoded = mb64.Decode(encoded);
  const content1 = decoded.toString();

  if (content1 !== content) {
    throw new Error(`content mismatch: '${content1}' !== '${content}'`);
  }

  console.log("✓ TestEncodeAndDecode passed");
}

function testEncodeAndDecodeCJK() {
  const key = "abcdefg";
  mb64.SetEncoding(key);
  const content = "こんにちは、世界。GO";

  const encoded = mb64.Encode(Buffer.from(content));
  const decoded = mb64.Decode(encoded);
  const content1 = decoded.toString();

  if (content1 !== content) {
    throw new Error(`content mismatch: '${content1}' !== '${content}'`);
  }

  console.log("✓ TestEncodeAndDecodeCJK passed");
}

function testIdempotence() {
  for (let i = 0; i < 50; i++) {
    const key = genRandomString(i + 1);
    console.log("TestIdempotence with key:", key);

    mb64.SetEncoding(key);
    const content = "test content";
    const encoded1 = mb64.Encode(Buffer.from(content));

    for (let j = 0; j < 1000; j++) {
      mb64.SetEncoding(key);
      const encoded2 = mb64.Encode(Buffer.from(content));
      const decoded2 = mb64.Decode(encoded2);

      if (decoded2.toString() !== content) {
        throw new Error(`idempotence failed for key: ${key}`);
      }

      const decoded21 = mb64.Decode(encoded1);

      if (decoded21.toString() !== content) {
        throw new Error(`idempotence failed for key: ${key}`);
      }
    }
  }
  console.log("✓ TestIdempotence passed");
}

function testEmptyKey() {
  try {
    mb64.SetEncoding("");
    throw new Error("✗ TestEmptyKey failed: should have thrown error");
  } catch (err) {
    if (err.message.includes("key cannot be empty")) {
      console.log("✓ TestEmptyKey passed");
    } else {
      throw new Error(`✗ TestEmptyKey failed: ${err.message}`);
    }
  }
}

function testLargeData() {
  mb64.SetEncoding("testkey");
  const largeContent = "x".repeat(10000);

  const encoded = mb64.Encode(Buffer.from(largeContent));
  const decoded = mb64.Decode(encoded);

  if (decoded.toString() !== largeContent) {
    throw new Error("large data test failed");
  }

  console.log("✓ TestLargeData passed");
}

function testRandomData() {
  mb64.SetEncoding("randomkey");

  for (let i = 0; i < 50; i++) {
    const randomContent = genRandomString(Math.floor(Math.random() * 1000) + 1);
    const encoded = mb64.Encode(Buffer.from(randomContent));
    const decoded = mb64.Decode(encoded);

    if (decoded.toString() !== randomContent) {
      throw new Error(`random data test failed for: ${randomContent}`);
    }
  }

  console.log("✓ TestRandomData passed");
}

function testBinaryData() {
  mb64.SetEncoding("binarykey");
  const binaryData = Buffer.from([0, 1, 2, 3, 255, 254, 253, 128, 127]);

  const encoded = mb64.Encode(binaryData);
  const decoded = mb64.Decode(encoded);

  if (!binaryData.equals(decoded)) {
    throw new Error("binary data test failed");
  }

  console.log("✓ TestBinaryData passed");
}

function testRenderFile() {
  const key = "filekey";
  const filepath = path.join(
    path.dirname(new URL(import.meta.url).pathname),
    "image.jpg",
  );
  const tmpdir = fs.mkdtempSync("/tmp/foo");
  const output = path.join(tmpdir, "decoded");
  const decodedFilepath = path.join(tmpdir, "image.jpg");

  mb64.RenderInFile(key, filepath, output);
  mb64.RenderOutFile(key, output, decodedFilepath);

  const hash1 = calculateSha256(filepath);
  const hash2 = calculateSha256(decodedFilepath);

  if (hash1 !== hash2) {
    throw new Error("sha256 mismatch");
  }

  fs.rmSync(tmpdir, { recursive: true, force: true });

  console.log("✓ TestRenderFile passed");
}

function calculateSha256(filepath) {
  const fileBuffer = fs.readFileSync(filepath);
  const hashSum = crypto.createHash("sha256");
  hashSum.update(fileBuffer);
  return hashSum.digest("hex");
}

console.log("Running mb64.js tests ...\n");

testBypass();
testSetEncodingAndBypass();
testBypassAndSetEncoding();
testEncodeAndDecode();
testEncodeAndDecodeCJK();
testIdempotence();
testEmptyKey();
testLargeData();
testRandomData();
testBinaryData();
testRenderFile();

console.log("\nAll tests completed.");
