#!/usr/bin/env python3.12

import base64
import ctypes
import os

lib_path = os.path.join(os.path.dirname(__file__), "build", "libmb64.so")
lib = ctypes.CDLL(lib_path)

lib.SetEncodingC.argtypes = [ctypes.c_char_p]
lib.SetEncodingC.restype = ctypes.c_int

lib.BypassC.argtypes = []
lib.BypassC.restype = None

lib.EncodeC.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_int)]
lib.EncodeC.restype = ctypes.c_int

lib.DecodeC.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_int)]
lib.DecodeC.restype = ctypes.c_int


class MB64:
    def __init__(self):
        pass

    def set_encoding(self, key: str) -> bool:
        result = lib.SetEncodingC(key.encode("utf-8"))
        return result == 0

    def bypass(self):
        lib.BypassC()

    def encode(self, data: bytes) -> bytes:
        result_ptr = ctypes.c_char_p()
        result_len = ctypes.c_int()

        ret = lib.EncodeC(data, len(data), ctypes.byref(result_ptr), ctypes.byref(result_len))
        if ret != 0:
            raise Exception("failed to encode")

        result = ctypes.string_at(result_ptr, result_len.value)
        return result

    def decode(self, data: bytes) -> bytes:
        result_ptr = ctypes.c_char_p()
        result_len = ctypes.c_int()

        ret = lib.DecodeC(data, len(data), ctypes.byref(result_ptr), ctypes.byref(result_len))
        if ret != 0:
            raise Exception("failed to decode")

        result = ctypes.string_at(result_ptr, result_len.value)
        return result


if __name__ == "__main__":
    mb64 = MB64()

    print("\n--- test encode/decode mode ---")

    mb64.set_encoding("testkey123")

    original_string = "Hello, 世界！"
    original_bytes = original_string.encode("utf-8")
    encoded = mb64.encode(original_bytes)
    decoded = mb64.decode(encoded)

    decoded_string = decoded.decode("utf-8")
    if original_string == decoded_string:
        print("--- test ok ---")
    else:
        raise Exception(f"{original_string} not equal to {decoded_string}")

    print("\n--- test bypass mode ---")
    mb64.bypass()

    b64_string = base64.b64encode(original_bytes).decode("utf-8")

    encoded_bytes_bypass = mb64.encode(original_bytes)
    encoded_string_bypass = encoded_bytes_bypass.decode("utf-8")

    if encoded_string_bypass == b64_string:
        print("--- test ok ---")
    else:
        raise Exception(f"{encoded_string_bypass} not equal to {b64_string}")

    decoded_bypass = mb64.decode(encoded_bytes_bypass)
    decoded_string_bypass = decoded_bypass.decode("utf-8")
    if original_string == decoded_string_bypass:
        print("--- test ok ---")
    else:
        raise Exception(f"{original_string} not equal to {decoded_string_bypass}")
