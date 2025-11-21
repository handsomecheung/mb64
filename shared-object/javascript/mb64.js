#!/usr/bin/env node

const koffi = require("koffi");
const path = require("path");

class MB64 {
    constructor() {
        const libPath = path.join(__dirname, "..", "..", "build", "libmb64.so");

        this.lib = koffi.load(libPath);

        this.SetEncodingC = this.lib.func("SetEncodingC", "int", ["str"]);
        this.BypassC = this.lib.func("BypassC", "void", []);
        this.EncodeC = this.lib.func("EncodeC", "int", ["char *", "int", "char **", "int *"]);
        this.DecodeC = this.lib.func("DecodeC", "int", ["char *", "int", "char **", "int *"]);
        this.FreeC = this.lib.func("FreeC", "void", ["void *"]);
    }

    setEncoding(key) {
        const result = this.SetEncodingC(key);
        return result === 0;
    }

    bypass() {
        this.BypassC();
    }

    encode(data) {
        const dataBuffer = Buffer.from(data);
        const dataArray = new Uint8Array(dataBuffer);

        // Allocate memory for output parameters
        const resultPtrPtr = koffi.alloc("char *", 1);
        const resultLenPtr = koffi.alloc("int", 1);

        const ret = this.EncodeC(
            dataArray,
            dataArray.length,
            resultPtrPtr,
            resultLenPtr,
        );

        if (ret !== 0) {
            throw new Error("Failed to encode");
        }

        try {
            const ptr = koffi.decode(resultPtrPtr, "char *");
            const len = koffi.decode(resultLenPtr, "int");

            // The C function returns a string, so we can use it directly
            return Buffer.from(ptr, 'utf-8');
        } finally {
            // We need to pass the original pointer address, not the decoded string
            const originalPtr = koffi.decode(resultPtrPtr, "void *");
            if (originalPtr !== null) {
                this.FreeC(originalPtr);
            }
        }
    }

    decode(data) {
        const dataBuffer = Buffer.from(data);
        const dataArray = new Uint8Array(dataBuffer);

        // Allocate memory for output parameters
        const resultPtrPtr = koffi.alloc("char *", 1);
        const resultLenPtr = koffi.alloc("int", 1);

        const ret = this.DecodeC(
            dataArray,
            dataArray.length,
            resultPtrPtr,
            resultLenPtr,
        );

        if (ret !== 0) {
            throw new Error("Failed to decode");
        }

        try {
            const ptr = koffi.decode(resultPtrPtr, "char *");
            const len = koffi.decode(resultLenPtr, "int");

            // The C function returns decoded data as a string
            return Buffer.from(ptr, 'utf-8');
        } finally {
            // We need to pass the original pointer address, not the decoded string
            const originalPtr = koffi.decode(resultPtrPtr, "void *");
            if (originalPtr !== null) {
                this.FreeC(originalPtr);
            }
        }
    }
}

module.exports = MB64;
