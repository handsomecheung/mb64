#!/usr/bin/env node

const MB64 = require('./mb64');

try {
    console.log("Creating MB64 instance...");
    const mb64 = new MB64();

    console.log("Setting encoding...");
    const result = mb64.setEncoding("testkey12345678");
    console.log("Set encoding result:", result);

    console.log("Testing encode...");
    const testData = Buffer.from("hello", 'utf-8');
    const encoded = mb64.encode(testData);
    console.log("Encoded:", encoded);

    console.log("Testing decode...");
    const decoded = mb64.decode(encoded);
    console.log("Decoded:", decoded);
    console.log("Decoded string:", decoded.toString('utf-8'));

    if (decoded.toString('utf-8') === "hello") {
        console.log("✓ Encode/decode test passed!");
    } else {
        throw new Error("Decoded data doesn't match original");
    }
} catch (error) {
    console.error("Test failed:", error.message);
    console.error(error.stack);
}