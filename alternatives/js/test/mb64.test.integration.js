import * as mb64 from "../mb64.js";
import { execSync } from "child_process";
import { strict as assert } from "assert";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const GO_BINARY_PATH = path.join(__dirname, "../../../build/mb64");

function testGoEncodeAndJSDecode() {
  console.log("  Running test: Go binary [encode] -> JS lib [decode]");
  const key = "abcdefg";
  mb64.SetEncoding(key);
  const expect_content = "hello world from go";

  const encoded = execSync(
    `${GO_BINARY_PATH} --key '${key}' encrypt '${expect_content}'`,
  ).toString();

  const decoded = mb64.Decode(encoded);
  const content = decoded.toString();

  assert.strictEqual(
    content,
    expect_content,
    `Go->JS content mismatch: '${content}' !== '${expect_content}'`,
  );

  console.log("  ✓ Test passed");
}

function testJSEncodeAndGoDecode() {
  console.log("  Running test: JS lib [encode] -> Go binary [decode]");
  const key = "abcdefg";
  mb64.SetEncoding(key);
  const expect_content = "hello world from js";

  const encoded = mb64.Encode(expect_content);

  const decoded = execSync(
    `${GO_BINARY_PATH} --key '${key}' decrypt '${encoded}'`,
  ).toString();

  assert.strictEqual(
    decoded,
    expect_content,
    `JS->Go content mismatch: '${decoded}' !== '${expect_content}'`,
  );

  console.log("  ✓ Test passed");
}

console.log("\nRunning mb64.js cross-language integration tests ...\n");

try {
  testGoEncodeAndJSDecode();
  testJSEncodeAndGoDecode();
  console.log("\n✅ All integration tests completed successfully.");
} catch (error) {
  console.error("\n❌ Integration tests failed:");
  console.error(error.message);
  process.exit(1);
}
