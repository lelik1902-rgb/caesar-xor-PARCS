# -*- coding: utf-8 -*-
"""Шифр Цезаря + XOR-шифрування тексту: послідовно та через PARCS.

Локальний послідовний запуск без сторонніх бібліотек:
    python caesar_xor.py --text-length 200000 --rounds 4
    python caesar_xor.py --input input_sequential.json --output result.json
    python caesar_xor.py --demo "Hello, PARCS!"

Для PARCS завантажте цей файл як Solution File, а JSON нижче як Input File:
    {"mode": "parallel", "text_length": 4000000, "seed": 42, "shift": 3,
     "key": "TK42-PARCS", "rounds": 8, "block_size": 65536}
Для послідовного запуску змініть mode на "sequential".
Штатний планувальник Hummer12007/parcs-python потребує підключеного воркера
навіть для sequential; сам послідовний алгоритм воркерів не викликає.

Один раунд шифрування байта p у позиції pos:
    1) шифр Цезаря: латинська літера зсувається на (shift + r) mod 26
       у межах свого регістру, інші байти не змінюються;
    2) XOR із байтом ключа key[(pos + r) mod len(key)].
Розшифрування виконує раунди у зворотному порядку: XOR, потім зворотний
зсув Цезаря. Кількість раундів збільшує обчислювальне навантаження.

Текст ділиться на блоки по block_size байтів. Для кожного блока шифротексту
рахується SHA-256, а підсумковий digest — SHA-256 від послідовності цих
хешів. Межі частин воркерів збігаються з межами блоків, тому digest не
залежить від кількості воркерів і однаковий для обох режимів. Кожен блок
після шифрування розшифровується й порівнюється з оригіналом.

elapsed_seconds включає передавання тексту воркерам, шифрування,
розшифрування, перевірку та збирання відповідей, але не генерацію тексту,
читання/запис файлів і запуск PARCS.

Синтаксис сумісний з Python 2.7 і Python 3. Для паралельного режиму потрібне
середовище PARCS із Pyro4 та асинхронними проксі, переданими планувальником.
"""

from __future__ import division, print_function

import argparse
import hashlib
import json
import random
import sys
import time

try:
    from Pyro4 import expose
    HAS_PYRO4 = True
except ImportError:
    HAS_PYRO4 = False

    def expose(method):
        return method

try:
    integer_types = (int, long)  # noqa: F821 - Python 2.7.
    iterate = xrange  # noqa: F821 - Python 2.7.
except NameError:
    integer_types = (int,)
    iterate = range

clock = getattr(time, "perf_counter", time.time)
CLOCK_NAME = "perf_counter" if hasattr(time, "perf_counter") else "time.time"

ALPHABET_SIZE = 26
WORDS_ALPHABET = "abcdefghijklmnopqrstuvwxyz"
PUNCTUATION = (",", ".", "!", "?", ";", ":")


def validate_config(raw):
    """Перевіряємо JSON до генерації даних і вимірювання алгоритму."""
    if not isinstance(raw, dict):
        raise ValueError("Input must be a JSON object.")
    allowed = ("mode", "text_length", "seed", "shift", "key", "rounds",
               "block_size")
    unknown = set(raw) - set(allowed)
    if unknown:
        raise ValueError("Unknown parameters: " + ", ".join(sorted(unknown)))

    config = {
        "mode": raw.get("mode", "sequential"),
        "text_length": raw.get("text_length"),
        "seed": raw.get("seed", 42),
        "shift": raw.get("shift", 3),
        "key": raw.get("key", "TK42-PARCS"),
        "rounds": raw.get("rounds", 8),
        "block_size": raw.get("block_size", 65536),
    }
    if config["mode"] not in ("sequential", "parallel"):
        raise ValueError("mode must be 'sequential' or 'parallel'.")
    for name in ("text_length", "seed", "shift", "rounds", "block_size"):
        value = config[name]
        if isinstance(value, bool) or not isinstance(value, integer_types):
            raise ValueError(name + " must be an integer.")
    if config["text_length"] < 1:
        raise ValueError("text_length must be positive.")
    if config["rounds"] < 1:
        raise ValueError("rounds must be at least 1.")
    if config["block_size"] < 1:
        raise ValueError("block_size must be positive.")
    key = config["key"]
    if not key or any(ord(char) > 127 for char in key):
        raise ValueError("key must be a non-empty ASCII string.")
    config["key"] = str(key)
    config["shift"] %= ALPHABET_SIZE
    return config


def generate_text(config):
    """Псевдовипадковий ASCII-текст зі «слів», пробілів і розділових знаків."""
    generator = random.Random(config["seed"])
    length = config["text_length"]
    parts = []
    produced = 0
    while produced < length:
        word = "".join(generator.choice(WORDS_ALPHABET)
                       for _ in iterate(generator.randint(1, 10)))
        if generator.random() < 0.15:
            word = word[0].upper() + word[1:]
        if generator.random() < 0.1:
            word += generator.choice(PUNCTUATION)
        word += " "
        parts.append(word)
        produced += len(word)
    return "".join(parts)[:length]


def to_bytes(text):
    """Pyro4 може передати рядок як str або unicode — приводимо до байтів."""
    if isinstance(text, bytes):
        return bytearray(text)
    return bytearray(text.encode("ascii"))


def caesar_tables(shift, rounds):
    """Таблиці 256 -> 256 для прямого і зворотного зсуву в кожному раунді."""
    forward_tables, backward_tables = [], []
    for round_index in iterate(rounds):
        step = (shift + round_index) % ALPHABET_SIZE
        forward = bytearray(range(256))
        backward = bytearray(range(256))
        for base in (ord("A"), ord("a")):
            for letter in iterate(ALPHABET_SIZE):
                source = base + letter
                target = base + (letter + step) % ALPHABET_SIZE
                forward[source] = target
                backward[target] = source
        forward_tables.append(forward)
        backward_tables.append(backward)
    return forward_tables, backward_tables


def encrypt_bytes(data, offset, shift, key, rounds):
    """Шифруємо копію data; offset — глобальна позиція першого байта."""
    result = bytearray(data)
    key_bytes = bytearray(key.encode("ascii") if not isinstance(key, bytes) else key)
    key_length = len(key_bytes)
    forward_tables = caesar_tables(shift, rounds)[0]
    for round_index in iterate(rounds):
        table = forward_tables[round_index]
        key_position = (offset + round_index) % key_length
        for index in iterate(len(result)):
            result[index] = table[result[index]] ^ key_bytes[key_position]
            key_position += 1
            if key_position == key_length:
                key_position = 0
    return result


def decrypt_bytes(data, offset, shift, key, rounds):
    """Обернене перетворення: раунди у зворотному порядку, XOR -> Цезар назад."""
    result = bytearray(data)
    key_bytes = bytearray(key.encode("ascii") if not isinstance(key, bytes) else key)
    key_length = len(key_bytes)
    backward_tables = caesar_tables(shift, rounds)[1]
    for round_index in reversed(range(rounds)):
        table = backward_tables[round_index]
        key_position = (offset + round_index) % key_length
        for index in iterate(len(result)):
            result[index] = table[result[index] ^ key_bytes[key_position]]
            key_position += 1
            if key_position == key_length:
                key_position = 0
    return result


def process_blocks(text, offset, block_size, shift, key, rounds):
    """Спільне ядро двох режимів: шифруємо, розшифровуємо й перевіряємо блоки.

    Повертає список SHA-256 (hex) блоків шифротексту, кількість оброблених
    байтів, кількість байтів, що не відновилися, і hex перших 16 байтів
    шифротексту (для ілюстрації у звіті).
    """
    data = to_bytes(text)
    digests = []
    mismatched = 0
    preview = ""
    for start in iterate(0, len(data), block_size):
        block = data[start:start + block_size]
        cipher = encrypt_bytes(block, offset + start, shift, key, rounds)
        restored = decrypt_bytes(cipher, offset + start, shift, key, rounds)
        if restored != block:
            mismatched += sum(1 for a, b in zip(restored, block) if a != b)
        digests.append(hashlib.sha256(bytes(cipher)).hexdigest())
        if start == 0:
            preview = "".join("%02x" % value for value in cipher[:16])
    return digests, len(data), mismatched, preview


def run_sequential(text, config):
    """Обробляємо весь текст у поточному процесі."""
    digests, processed, mismatched, preview = process_blocks(
        text, 0, config["block_size"], config["shift"], config["key"],
        config["rounds"])
    return digests, processed, mismatched, preview, 0


def split_by_blocks(length, block_size, parts):
    """Ділимо [0, length) на parts частин, межі яких кратні block_size."""
    blocks = (length + block_size - 1) // block_size
    parts = min(parts, blocks)
    bounds = []
    for index in iterate(parts):
        first = blocks * index // parts * block_size
        last = min(blocks * (index + 1) // parts * block_size, length)
        bounds.append((first, last))
    return bounds


def run_parallel(text, config, workers):
    """Кожен worker отримує свою частину тексту та її глобальне зміщення."""
    if not HAS_PYRO4:
        raise RuntimeError("Parallel mode requires Pyro4 in the PARCS environment.")
    if not workers:
        raise RuntimeError("Parallel mode requires connected PARCS workers.")

    bounds = split_by_blocks(len(text), config["block_size"], len(workers))
    pending_results = []
    for index, (first, last) in enumerate(bounds):
        pending_results.append(workers[index].process_part(
            text[first:last], first, config["block_size"], config["shift"],
            config["key"], config["rounds"]
        ))

    # Усі запити вже відправлені; тепер очікуємо результати в порядку частин.
    digests = []
    processed = 0
    mismatched = 0
    preview = ""
    for index, pending in enumerate(pending_results):
        part_digests, part_processed, part_mismatched, part_preview = pending.value
        digests.extend(part_digests)
        processed += part_processed
        mismatched += part_mismatched
        if index == 0:
            preview = part_preview
    return digests, processed, mismatched, preview, len(bounds)


def encrypt_text(raw_config, workers=None):
    """Готуємо однаковий текст і окремо вимірюємо обчислення обраного режиму."""
    config = validate_config(raw_config)
    generation_started = clock()
    text = generate_text(config)
    generation_elapsed = clock() - generation_started

    started = clock()
    if config["mode"] == "sequential":
        result = run_sequential(text, config)
    else:
        result = run_parallel(text, config, workers)
    digests, processed, mismatched, preview, workers_used = result
    elapsed = clock() - started

    expected_blocks = (len(text) + config["block_size"] - 1) // config["block_size"]
    if processed != len(text) or len(digests) != expected_blocks:
        raise RuntimeError("Invalid result: processed sizes are inconsistent.")
    final_digest = hashlib.sha256("".join(digests).encode("ascii")).hexdigest()
    return {
        "mode": config["mode"],
        "text_length": len(text),
        "processed_bytes": processed,
        "blocks": len(digests),
        "block_size": config["block_size"],
        "rounds": config["rounds"],
        "shift": config["shift"],
        "key": config["key"],
        "seed": config["seed"],
        "byte_operations": 2 * config["rounds"] * processed,
        "decryption_ok": mismatched == 0,
        "mismatched_bytes": mismatched,
        "ciphertext_sha256": final_digest,
        "ciphertext_preview_hex": preview,
        "plaintext_preview": text[:16],
        "elapsed_seconds": elapsed,
        "data_generation_seconds": generation_elapsed,
        "workers_used": workers_used,
        "timer": CLOCK_NAME,
    }


class Solver(object):
    """Контракт завантажуваної задачі Hummer12007/parcs-python."""

    def __init__(self, workers=None, input_file_name=None, output_file_name=None):
        self.workers = workers
        self.input_file_name = input_file_name
        self.output_file_name = output_file_name

    def solve(self):
        with open(self.input_file_name, "r") as source:
            config = json.load(source)
        result = encrypt_text(config, self.workers)
        text = json.dumps(result, indent=2, sort_keys=True)
        with open(self.output_file_name, "w") as destination:
            destination.write(text + "\n")
        print(text)
        return result

    @staticmethod
    @expose
    def process_part(text, offset, block_size, shift, key, rounds):
        """Віддалений метод, що виконується на worker."""
        return process_blocks(text, offset, block_size, shift, key, rounds)


def demo(phrase, shift, key, rounds):
    """Наочний приклад для звіту: відкритий текст -> шифротекст -> назад."""
    data = to_bytes(phrase)
    caesar_table = caesar_tables(shift, 1)[0][0]
    one_round_caesar = bytearray(caesar_table[value] for value in data)
    cipher = encrypt_bytes(data, 0, shift, key, rounds)
    restored = decrypt_bytes(cipher, 0, shift, key, rounds)
    print("Plaintext:          " + phrase)
    print("Caesar only (r=0):  " + one_round_caesar.decode("ascii"))
    print("Ciphertext (hex):   " + "".join("%02x" % value for value in cipher))
    print("Decrypted:          " + restored.decode("ascii"))
    print("Restored correctly: " + str(restored == data))


def main():
    parser = argparse.ArgumentParser(description="Caesar + XOR cipher / PARCS-Python")
    parser.add_argument("--input", help="Input JSON; otherwise use CLI parameters.")
    parser.add_argument("--output", help="Save result JSON to this path.")
    parser.add_argument("--text-length", type=int, default=200000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--shift", type=int, default=3)
    parser.add_argument("--key", default="TK42-PARCS")
    parser.add_argument("--rounds", type=int, default=8)
    parser.add_argument("--block-size", type=int, default=65536)
    parser.add_argument("--demo", help="Encrypt and decrypt a short ASCII phrase.")
    args = parser.parse_args()

    try:
        if args.demo is not None:
            demo(args.demo, args.shift % ALPHABET_SIZE, args.key, args.rounds)
            return 0
        if args.input:
            with open(args.input, "r") as source:
                config = json.load(source)
        else:
            config = {"mode": "sequential", "text_length": args.text_length,
                      "seed": args.seed, "shift": args.shift, "key": args.key,
                      "rounds": args.rounds, "block_size": args.block_size}
        if isinstance(config, dict) and config.get("mode") == "parallel":
            raise ValueError("Use the PARCS web interface for parallel mode; "
                             "this CLI runs the sequential version only.")
        result = encrypt_text(config)
        text = json.dumps(result, indent=2, sort_keys=True)
        if args.output:
            with open(args.output, "w") as destination:
                destination.write(text + "\n")
        print(text)
        return 0
    except (ValueError, RuntimeError, IOError, UnicodeError) as error:
        print("Error: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
