#!/usr/bin/env python3.12

import ctypes
import os


class MB64:
    def __init__(self):
        self.lib_path = os.path.join(os.path.dirname(__file__), "build", "libmb64.so")
        self.lib = ctypes.CDLL(self.lib_path)

        self.lib.SetEncodingC.argtypes = [ctypes.c_char_p]
        self.lib.SetEncodingC.restype = ctypes.c_int

        self.lib.BypassC.argtypes = []
        self.lib.BypassC.restype = None

        self.lib.EncodeC.argtypes = [
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.POINTER(ctypes.c_int),
        ]
        self.lib.EncodeC.restype = ctypes.c_int

        self.lib.DecodeC.argtypes = [
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.POINTER(ctypes.c_int),
        ]
        self.lib.DecodeC.restype = ctypes.c_int

    def set_encoding(self, key: str) -> bool:
        result = self.lib.SetEncodingC(key.encode("utf-8"))
        return result == 0

    def bypass(self):
        self.lib.BypassC()

    def encode(self, data: bytes) -> bytes:
        result_ptr = ctypes.c_char_p()
        result_len = ctypes.c_int()

        ret = self.lib.EncodeC(data, len(data), ctypes.byref(result_ptr), ctypes.byref(result_len))
        if ret != 0:
            raise Exception("failed to encode")

        try:
            result = ctypes.string_at(result_ptr, result_len.value)
            return result
        finally:
            # Free the memory allocated by C library
            # Only free if the C function succeeded and allocated memory
            if result_ptr.value:
                self.lib.FreeC(result_ptr)

    def decode(self, data: bytes) -> bytes:
        result_ptr = ctypes.c_char_p()
        result_len = ctypes.c_int()

        ret = self.lib.DecodeC(data, len(data), ctypes.byref(result_ptr), ctypes.byref(result_len))
        if ret != 0:
            raise Exception("failed to decode")

        try:
            result = ctypes.string_at(result_ptr, result_len.value)
            return result
        finally:
            # Free the memory allocated by C library
            # Only free if the C function succeeded and allocated memory
            if result_ptr.value:
                self.lib.FreeC(result_ptr)
