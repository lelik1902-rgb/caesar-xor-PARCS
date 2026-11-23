# -*- coding: utf-8 -*-
"""Збирає результати прогонів у таблиці для звіту.

Збережіть вихідні файли PARCS (Output, це JSON) у папку results/ з іменами:
    seq_1.txt seq_2.txt seq_3.txt      - послідовна версія
    w1_1.txt  w1_2.txt  w1_3.txt       - PARCS, 1 воркер
    w2_1.txt ...  w4_3.txt             - PARCS, 2 і 4 воркери
Запуск:  python make_tables.py [results]
"""

from __future__ import division, print_function

import glob
import json
import os
import sys

CONFIGS = [("seq", "Послідовна версія", None),
           ("w1", "PARCS, воркерів 1", 1),
           ("w2", "PARCS, воркерів 2", 2),
           ("w4", "PARCS, воркерів 4", 4)]


def fmt(value, digits=3):
    return ("%.*f" % (digits, value)).replace(".", ",")


def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else "results"
    runs = {}
    digests = set()
    for prefix, _, _ in CONFIGS:
        files = sorted(glob.glob(os.path.join(folder, prefix + "_*.txt")))
        runs[prefix] = []
        for path in files:
            with open(path) as source:
                data = json.load(source)
            if not data["decryption_ok"]:
                print("УВАГА: розшифрування не збіглося у " + path)
            digests.add(data["ciphertext_sha256"])
            runs[prefix].append(data["elapsed_seconds"])

    if not runs["seq"]:
        print("Немає файлів seq_*.txt у папці " + folder)
        return 1
    base = sum(runs["seq"]) / len(runs["seq"])

    print("Таблиця 1 — Час виконання окремих прогонів у секундах")
    for prefix, title, _ in CONFIGS:
        print("%-22s %s" % (title, "  ".join(fmt(t) for t in runs[prefix])))

    print("\nТаблиця 2 — Середній час і показники прискорення")
    for prefix, title, workers in CONFIGS:
        if not runs[prefix]:
            continue
        mean = sum(runs[prefix]) / len(runs[prefix])
        speedup = base / mean
        efficiency = "—" if workers is None else fmt(100 * speedup / workers, 1)
        print("%-22s %10s %8s %8s" % (title, fmt(mean), fmt(speedup, 2), efficiency))

    print("\nРізних SHA-256 шифротексту: %d (має бути 1)" % len(digests))
    for digest in digests:
        print("  " + digest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
