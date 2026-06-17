"""
#Вариант 12. Частотный анализ атак с использованием Counter (сложность - ***)

За сутки на сервере зафиксированы тысячи попыток вторжения. Логи содержат записи:
```
временная метка, тип атаки, IP-адрес источника, целевой порт
```
Требуется быстро выявить самые распространённые угрозы и наиболее активных злоумышленников.

**Задачи:**

1. Используя Counter, определите:

* топ-5 самых частых типов атак;

* топ-10 IP-адресов источников атак;

* топ-5 целевых портов (если есть информация).

2. Найдите типы атак, которые встречаются реже всего (например, менее 5 раз) – это могут быть новые или редкие методы.

3. Постройте распределение количества атак по часам (если есть временные метки). Для группировки по часам можно использовать defaultdict(list) или Counter с преобразованием времени в час.

4. Выявите, существуют ли IP-адреса, специализирующиеся на конкретном типе атак. Используйте вложенный Counter:
```
{ip: Counter({attack_type: count})}).
```
**Цель:**

Использовать Counter для частотного анализа и выявления закономерностей в данных.

**Коллекции:**
* Counter из модуля collections
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Optional


LogRecord = Dict[str, str]


def parse_timestamp(value: str) -> Optional[datetime]:
    """Преобразует строковую временную метку в datetime.

    Поддерживаются популярные форматы:
    - 2026-06-16 13:45:00
    - 2026-06-16T13:45:00
    - 2026-06-16T13:45:00Z
    """
    value = value.strip()
    if not value:
        return None

    formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%d.%m.%Y %H:%M:%S",
    )

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue

    return None


def read_logs(path: Path) -> list[LogRecord]:
    """Считывает CSV-файл с логами атак."""
    if not path.exists():
        raise FileNotFoundError(f"Файл не найден: {path}")

    with path.open("r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        required_columns = {"timestamp", "attack_type", "source_ip", "target_port"}
        actual_columns = set(reader.fieldnames or [])

        missing_columns = required_columns - actual_columns
        if missing_columns:
            raise ValueError(
                "В CSV отсутствуют обязательные столбцы: "
                + ", ".join(sorted(missing_columns))
            )

        return [row for row in reader]


def print_counter(title: str, counter: Counter, limit: Optional[int] = None) -> None:
    """Печатает элементы Counter в удобном виде."""
    print(f"\n{title}")
    print("-" * len(title))

    items = counter.most_common(limit)
    if not items:
        print("Нет данных")
        return

    for index, (item, count) in enumerate(items, start=1):
        print(f"{index:>2}. {item:<20} — {count}")


def analyze_logs(
    logs: Iterable[LogRecord],
    rare_threshold: int = 5,
    specialization_threshold: float = 0.80,
    min_ip_attacks: int = 10,
) -> None:
    """Выполняет частотный анализ логов атак."""
    attack_type_counter: Counter[str] = Counter()
    source_ip_counter: Counter[str] = Counter()
    target_port_counter: Counter[str] = Counter()
    attacks_by_hour: Counter[int] = Counter()
    hourly_records: defaultdict[int, list[LogRecord]] = defaultdict(list)
    attacks_by_ip: defaultdict[str, Counter[str]] = defaultdict(Counter)

    total_records = 0

    for row in logs:
        total_records += 1

        attack_type = row.get("attack_type", "").strip() or "UNKNOWN"
        source_ip = row.get("source_ip", "").strip() or "UNKNOWN"
        target_port = row.get("target_port", "").strip()
        timestamp = parse_timestamp(row.get("timestamp", ""))

        attack_type_counter[attack_type] += 1
        source_ip_counter[source_ip] += 1
        attacks_by_ip[source_ip][attack_type] += 1

        if target_port:
            target_port_counter[target_port] += 1

        if timestamp is not None:
            attacks_by_hour[timestamp.hour] += 1
            hourly_records[timestamp.hour].append(row)

    print("частотный аналзи атак")
    print("=" * 24)
    print(f"Всего записей обработано: {total_records}")

    print_counter("Топ-5 самых частых типов атак", attack_type_counter, limit=5)
    print_counter("Топ-10 IP-адресов источников атак", source_ip_counter, limit=10)
    print_counter("Топ-5 целевых портов", target_port_counter, limit=5)

    rare_attacks = Counter(
        {
            attack_type: count
            for attack_type, count in attack_type_counter.items()
            if count < rare_threshold
        }
    )
    print_counter(
        f"Редкие типы атак, встречающиеся менее {rare_threshold} раз",
        Counter(dict(sorted(rare_attacks.items(), key=lambda item: item[1]))),
    )

    print("\nРаспределение атак по часам")
    if attacks_by_hour:
        for hour in range(24):
            count = attacks_by_hour.get(hour, 0)
            bar = "#" * min(count // 10, 60)
            print(f"{hour:02d}:00–{hour:02d}:59 — {count:>4} {bar}")
    else:
        print("Временные метки отсутствуют или имеют неизвестный формат")

    print("\nIP-адреса, специализирующиеся на конкретном типе атак")
    found_specialists = False

    for ip, counter in sorted(
        attacks_by_ip.items(),
        key=lambda item: sum(item[1].values()),
        reverse=True,
    ):
        total_ip_attacks = sum(counter.values())
        main_attack, main_count = counter.most_common(1)[0]
        share = main_count / total_ip_attacks

        if total_ip_attacks >= min_ip_attacks and share >= specialization_threshold:
            found_specialists = True
            print(
                f"{ip:<15} — {main_attack:<18} "
                f"{main_count}/{total_ip_attacks} атак ({share:.0%})"
            )

    if not found_specialists:
        print("Явной специализации не найдено")

    print("\nВложенный Counter по IP")
    for ip, counter in source_ip_counter.most_common(10):
        print(f"{ip}: {dict(attacks_by_ip[ip].most_common())}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Частотный анализ атак с использованием collections.Counter"
    )
    parser.add_argument(
        "--file",
        default="sample_logs.csv",
        help="Путь к CSV-файлу с логами. По умолчанию: sample_logs.csv",
    )
    parser.add_argument(
        "--rare-threshold",
        type=int,
        default=5,
        help="Порог редкости типа атаки. По умолчанию: 5",
    )
    parser.add_argument(
        "--specialization-threshold",
        type=float,
        default=0.80,
        help="Доля одного типа атаки для признания IP специализированным. По умолчанию: 0.80",
    )
    parser.add_argument(
        "--min-ip-attacks",
        type=int,
        default=10,
        help="Минимальное количество атак от IP для анализа специализации. По умолчанию: 10",
    )
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    logs = read_logs(Path(args.file))
    analyze_logs(
        logs,
        rare_threshold=args.rare_threshold,
        specialization_threshold=args.specialization_threshold,
        min_ip_attacks=args.min_ip_attacks,
    )


if __name__ == "__main__":
    main()
