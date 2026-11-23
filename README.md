# Шифр Цезаря / XOR-шифрування у PARCS

Лабораторна робота 1 з дисципліни «Хмарні обчислення», група ТК-42.
Реалізація на [PARCS Python](https://github.com/Hummer12007/parcs-python).

## Файли

| Файл | Призначення |
|---|---|
| `caesar_xor.py` | Solution File для PARCS + CLI для послідовного запуску |
| `input_sequential.json` | Input File, послідовний режим |
| `input_parallel.json` | Input File, паралельний режим |
| `make_tables.py` | Збирає результати прогонів у таблиці 1 і 2 для звіту |

## Алгоритм

Один раунд для байта `p` у глобальній позиції `pos`:
1. Шифр Цезаря: латинська літера зсувається на `(shift + r) mod 26` у межах регістру.
2. XOR з байтом ключа `key[(pos + r) mod len(key)]`.

Виконується `rounds` раундів. Розшифрування йде у зворотному порядку (XOR, потім зсув назад).
Текст ділиться на блоки по `block_size` байтів. Master дає кожному воркеру суцільну частину тексту, межі якої кратні блоку, разом із глобальним зміщенням.
Воркер шифрує, розшифровує, звіряє з оригіналом і повертає SHA-256 кожного блока.
Підсумковий `ciphertext_sha256` однаковий для будь-якої кількості воркерів.

Швидко перевірити:
```
python caesar_xor.py --demo "Hello, PARCS!"
python caesar_xor.py --text-length 200000 --rounds 4
```

## Запуск у Google Cloud

Кожен вузол (master і кожен воркер) — окрема VM.

Так само, як у README PARCS Python:
```
gcloud config set compute/zone europe-north1-a
gcloud compute firewall-rules create allow-all --direction=INGRESS --priority=1000 --network=default --action=ALLOW --rules=all --source-ranges=0.0.0.0/0
gcloud compute instances create-with-container master --machine-type=e2-standard-2 --container-image=registry.hub.docker.com/hummer12007/parcs-node --container-env PARCS_ARGS="master"
# INTERNAL_IP master-а підставити замість 10.166.0.2
gcloud compute instances create-with-container worker1 worker2 worker3 worker4 --machine-type=e2-standard-2 --container-image=registry.hub.docker.com/hummer12007/parcs-node --container-env PARCS_ARGS="worker 10.166.0.2"
```
Веб-інтерфейс: `http://EXTERNAL_IP_MASTER:8080`.

## Експеримент

1. Послідовний запуск: Solution File = `caesar_xor.py`, Input File = `input_sequential.json`.
   Для послідовної версії PARCS однаково потребує хоча б одного підключеного воркера.
2. Паралельний запуск: Input File = `input_parallel.json`, із 1, 2 і 4 увімкненими воркерами.
   Зайвих воркерів вимикайте у вебінтерфейсі.
3. Кожну конфігурацію запустіть 3 рази. Output кожного прогону збережіть у `results/`
   як `seq_1.txt … seq_3.txt`, `w1_1.txt …`, `w2_…`, `w4_…`.
4. Запустіть `python make_tables.py` і перенесіть числа у звіт.

Якщо послідовна версія працює значно довше 2–3 хв або коротше 30 с, змініть `rounds` в обох JSON (час пропорційний `rounds`).

## Результати (Google Cloud, 1 master + 4 воркери e2-standard-2, europe-north1-a)

| Конфігурація | Середній час, с | Прискорення | Ефективність, % |
|---|---|---|---|
| Послідовна версія | 117,626 | 1,00 | — |
| PARCS, воркерів 1 | 120,922 | 0,97 | 97,3 |
| PARCS, воркерів 2 | 60,079 | 1,96 | 97,9 |
| PARCS, воркерів 4 | 31,024 | 3,79 | 94,8 |

У всіх 12 прогонах `decryption_ok = true`, `ciphertext_sha256 = d97b2cf92f146f56e350a60285384fe83c8779dd84a137ecce12bb52a9461099`.
