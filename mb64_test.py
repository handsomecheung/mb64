#!/usr/bin/env python3.12

import base64
import threading
import multiprocessing
import os
import psutil
import gc

from mb64 import MB64


def run_singleton(mb64):
    original_string = "世界へようこそ〜" * 100000
    original_bytes = original_string.encode("utf-8")
    encoded = mb64.encode(original_bytes)
    decoded = mb64.decode(encoded)

    decoded_string = decoded.decode("utf-8")
    if original_string != decoded_string:
        raise Exception(f"{original_string} not equal to {decoded_string}")

    print("\n--- test bypass mode ---")
    mb64.bypass()

    b64_string = base64.b64encode(original_bytes).decode("utf-8")

    encoded_bytes_bypass = mb64.encode(original_bytes)
    encoded_string_bypass = encoded_bytes_bypass.decode("utf-8")

    if encoded_string_bypass != b64_string:
        raise Exception(f"{encoded_string_bypass} not equal to {b64_string}")

    decoded_bypass = mb64.decode(encoded_bytes_bypass)
    decoded_string_bypass = decoded_bypass.decode("utf-8")
    if original_string != decoded_string_bypass:
        raise Exception(f"{original_string} not equal to {decoded_string_bypass}")


def run_singleton_with_process():
    mb64 = MB64()
    mb64.set_encoding("testkey12345678")
    run_singleton(mb64)


def test_memory_leak():
    print("Testing MB64 memory leak ...")

    mb64 = MB64()
    mb64.set_encoding("testkey12345678")

    process = psutil.Process(os.getpid())
    initial_memory = process.memory_info().rss / 1024 / 1024  # MB

    test_data = ("世界へようこそ〜" * 4000).encode("utf-8")
    print(f"Test data size: {len(test_data)} bytes")

    print(f"Initial memory usage: {initial_memory:.2f} MB")

    iterations = 100
    for i in range(iterations):
        if i % 10 == 0:
            print(f"Iteration {i}/{iterations}")

        encoded = mb64.encode(test_data)
        decoded = mb64.decode(encoded)
        if decoded != test_data:
            print("ERROR: Data integrity check failed!")
            return False

        if i % 10 == 0:
            gc.collect()

    final_memory = process.memory_info().rss / 1024 / 1024  # MB
    memory_increase = final_memory - initial_memory

    print(f"Final memory usage: {final_memory:.2f} MB")
    print(f"Memory increase: {memory_increase:.2f} MB")

    # Check if memory increase is reasonable (should be minimal)
    # Less than 10MB increase is acceptable
    if memory_increase < 10:
        print("✓ Memory leak test PASSED")
    else:
        raise Exception("✗ Memory leak test FAILED - significant memory increase detected")


def test_normal():
    print("--- test normal ---")

    mb64 = MB64()
    mb64.set_encoding("testkey12345678")

    run_singleton(mb64)


def test_multiplethreads():
    print("--- test multiplethreads ---")

    mb64 = MB64()
    mb64.set_encoding("testkey12345678")

    threads = []
    for i in range(200):
        t = threading.Thread(target=run_singleton, args=(mb64,))
        t.start()
        threads.append(t)

    print("wait for threads ...")
    for t in threads:
        print("wait for thread: ", t)
        t.join()

    print("multiple threads test ok")


def test_multipleprocesses():
    print("--- test multipleprocesses ---")

    # avoid dead lock
    multiprocessing.set_start_method("spawn")

    processes = []
    for i in range(200):
        p = multiprocessing.Process(target=run_singleton_with_process)

        p.start()
        processes.append(p)

    print("wait for processes ...")
    for p in processes:
        print("wait for process: ", p)
        p.join()

    print("multiple processes test ok")


if __name__ == "__main__":
    test_normal()
    test_memory_leak()
    test_multiplethreads()
    test_multipleprocesses()
