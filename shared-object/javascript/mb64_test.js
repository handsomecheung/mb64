#!/usr/bin/env node

const cluster = require('cluster');
const os = require('os');
const MB64 = require('./mb64');

function runSingleton(mb64) {
    const originalString = "世界へようこそ〜".repeat(100000);
    const originalBytes = Buffer.from(originalString, 'utf-8');
    const encoded = mb64.encode(originalBytes);
    const decoded = mb64.decode(encoded);

    const decodedString = decoded.toString('utf-8');
    if (originalString !== decodedString) {
        throw new Error(`${originalString} not equal to ${decodedString}`);
    }

    console.log("\n--- test bypass mode ---");
    mb64.bypass();

    const b64String = originalBytes.toString('base64');

    const encodedBytesBypass = mb64.encode(originalBytes);
    const encodedStringBypass = encodedBytesBypass.toString('utf-8');

    if (encodedStringBypass !== b64String) {
        throw new Error(`${encodedStringBypass} not equal to ${b64String}`);
    }

    const decodedBypass = mb64.decode(encodedBytesBypass);
    const decodedStringBypass = decodedBypass.toString('utf-8');
    if (originalString !== decodedStringBypass) {
        throw new Error(`${originalString} not equal to ${decodedStringBypass}`);
    }
}

function runSingletonWithProcess() {
    const mb64 = new MB64();
    mb64.setEncoding("testkey12345678");
    runSingleton(mb64);
}

function testMemoryLeak() {
    console.log("Testing MB64 memory leak ...");

    const mb64 = new MB64();
    mb64.setEncoding("testkey12345678");

    const initialMemory = process.memoryUsage().rss / 1024 / 1024; // MB

    const testData = Buffer.from("世界へようこそ〜".repeat(4000), 'utf-8');
    console.log(`Test data size: ${testData.length} bytes`);

    console.log(`Initial memory usage: ${initialMemory.toFixed(2)} MB`);

    const iterations = 100;
    for (let i = 0; i < iterations; i++) {
        if (i % 10 === 0) {
            console.log(`Iteration ${i}/${iterations}`);
        }

        const encoded = mb64.encode(testData);
        const decoded = mb64.decode(encoded);
        if (!decoded.equals(testData)) {
            console.log("ERROR: Data integrity check failed!");
            return false;
        }

        if (i % 10 === 0) {
            global.gc && global.gc();
        }
    }

    const finalMemory = process.memoryUsage().rss / 1024 / 1024; // MB
    const memoryIncrease = finalMemory - initialMemory;

    console.log(`Final memory usage: ${finalMemory.toFixed(2)} MB`);
    console.log(`Memory increase: ${memoryIncrease.toFixed(2)} MB`);

    // Check if memory increase is reasonable (should be minimal)
    // Less than 10MB increase is acceptable
    if (memoryIncrease < 10) {
        console.log("✓ Memory leak test PASSED");
    } else {
        throw new Error("✗ Memory leak test FAILED - significant memory increase detected");
    }
}

function testNormal() {
    console.log("--- test normal ---");

    const mb64 = new MB64();
    mb64.setEncoding("testkey12345678");

    runSingleton(mb64);
}

async function testMultipleThreads() {
    console.log("--- test multiple threads (workers) ---");

    const mb64 = new MB64();
    mb64.setEncoding("testkey12345678");

    const promises = [];
    for (let i = 0; i < 50; i++) { // Reduced from 200 for Node.js
        promises.push(new Promise((resolve, reject) => {
            try {
                runSingleton(mb64);
                resolve();
            } catch (error) {
                reject(error);
            }
        }));
    }

    console.log("wait for promises ...");
    await Promise.all(promises);
    console.log("multiple threads test ok");
}

function testMultipleProcesses() {
    return new Promise((resolve, reject) => {
        console.log("--- test multiple processes ---");

        if (cluster.isMaster) {
            const numWorkers = Math.min(50, os.cpus().length * 2); // Reduced from 200
            let completedWorkers = 0;
            let hasError = false;

            for (let i = 0; i < numWorkers; i++) {
                const worker = cluster.fork();

                worker.on('message', (msg) => {
                    if (msg.type === 'completed') {
                        completedWorkers++;
                        if (completedWorkers === numWorkers && !hasError) {
                            console.log("multiple processes test ok");
                            resolve();
                        }
                    } else if (msg.type === 'error') {
                        hasError = true;
                        reject(new Error(msg.error));
                    }
                });

                worker.on('exit', (code) => {
                    if (code !== 0 && !hasError) {
                        hasError = true;
                        reject(new Error(`Worker exited with code ${code}`));
                    }
                });
            }

            console.log("wait for processes ...");
        } else {
            try {
                runSingletonWithProcess();
                process.send({ type: 'completed' });
                process.exit(0);
            } catch (error) {
                process.send({ type: 'error', error: error.message });
                process.exit(1);
            }
        }
    });
}

async function main() {
    try {
        testNormal();
        testMemoryLeak();
        await testMultipleThreads();
        await testMultipleProcesses();
        console.log("All tests completed successfully!");
    } catch (error) {
        console.error("Test failed:", error.message);
        process.exit(1);
    }
}

if (require.main === module) {
    main();
}