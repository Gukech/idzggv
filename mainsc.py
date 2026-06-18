"""
# Вариант 12. Частотный анализ атак с использованием Counter

Логи содержат записи:
временная метка, тип атаки, IP-адрес источника, целевой порт

Программа:
1. Находит топ-5 типов атак.
2. Находит топ-10 IP-адресов источников атак.
3. Находит топ-5 целевых портов.
4. Ищет редкие типы атак.
5. Строит распределение атак по часам.
6. Определяет IP, специализирующиеся на конкретном типе атак.
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
    """Преобразует строковую временную метку в datetime."""
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


class AttackAnalyzer:
    """Класс для частотного анализа логов атак."""

    def __init__(
        self,
        logs: Iterable[LogRecord],
        rare_threshold: int = 5,
        specialization_threshold: float = 0.80,
        min_ip_attacks: int = 10,
    ) -> None:
        self.logs = list(logs)
        self.rare_threshold = rare_threshold
        self.specialization_threshold = specialization_threshold
        self.min_ip_attacks = min_ip_attacks

        self.attack_type_counter: Counter[str] = Counter()
        self.source_ip_counter: Counter[str] = Counter()
        self.target_port_counter: Counter[str] = Counter()
        self.attacks_by_hour: Counter[int] = Counter()
        self.hourly_records: defaultdict[int, list[LogRecord]] = defaultdict(list)
        self.attacks_by_ip: defaultdict[str, Counter[str]] = defaultdict(Counter)

        self.total_records = 0

    def analyze(self) -> None:
        """Обрабатывает все записи логов и заполняет счетчики."""
        for row in self.logs:
            self.total_records += 1

            attack_type = row.get("attack_type", "").strip() or "UNKNOWN"
            source_ip = row.get("source_ip", "").strip() or "UNKNOWN"
            target_port = row.get("target_port", "").strip()
            timestamp = parse_timestamp(row.get("timestamp", ""))

            self.attack_type_counter[attack_type] += 1
            self.source_ip_counter[source_ip] += 1
            self.attacks_by_ip[source_ip][attack_type] += 1

            if target_port:
                self.target_port_counter[target_port] += 1

            if timestamp is not None:
                self.attacks_by_hour[timestamp.hour] += 1
                self.hourly_records[timestamp.hour].append(row)

    def top_attack_types(self, limit: int = 5) -> list[tuple[str, int]]:
        """Возвращает самые частые типы атак."""
        return self.attack_type_counter.most_common(limit)

    def top_source_ips(self, limit: int = 10) -> list[tuple[str, int]]:
        """Возвращает самые активные IP-адреса."""
        return self.source_ip_counter.most_common(limit)

    def top_target_ports(self, limit: int = 5) -> list[tuple[str, int]]:
        """Возвращает самые частые целевые порты."""
        return self.target_port_counter.most_common(limit)

    def rare_attacks(self) -> Counter[str]:
        """Возвращает редкие типы атак."""
        return Counter(
            {
                attack_type: count
                for attack_type, count in self.attack_type_counter.items()
                if count < self.rare_threshold
            }
        )

    def specialized_ips(self) -> list[tuple[str, str, int, int, float]]:
        """
        Возвращает IP-адреса, которые специализируются на одном типе атак.

        Формат результата:
        ip, основной тип атаки, количество таких атак, всего атак, доля
        """
        result = []

        for ip, counter in self.attacks_by_ip.items():
            total_ip_attacks = sum(counter.values())

            if total_ip_attacks == 0:
                continue

            main_attack, main_count = counter.most_common(1)[0]
            share = main_count / total_ip_attacks

            if (
                total_ip_attacks >= self.min_ip_attacks
                and share >= self.specialization_threshold
            ):
                result.append((ip, main_attack, main_count, total_ip_attacks, share))

        return result

    def print_report(self) -> None:
        """Печатает полный отчет по результатам анализа."""
        print("ЧАСТОТНЫЙ АНАЛИЗ АТАК")
        print("=" * 24)
        print(f"Всего записей обработано: {self.total_records}")

        print_counter(
            "Топ-5 самых частых типов атак",
            self.attack_type_counter,
            limit=5,
        )

        print_counter(
            "Топ-10 IP-адресов источников атак",
            self.source_ip_counter,
            limit=10,
        )

        print_counter(
            "Топ-5 целевых портов",
            self.target_port_counter,
            limit=5,
        )

        rare_attacks = Counter(
            dict(sorted(self.rare_attacks().items(), key=lambda item: item[1]))
        )

        print_counter(
            f"Редкие типы атак, встречающиеся менее {self.rare_threshold} раз",
            rare_attacks,
        )

        print("\nРаспределение атак по часам")
        print("-------------------------")

        if self.attacks_by_hour:
            for hour in range(24):
                count = self.attacks_by_hour.get(hour, 0)
                bar = "#" * min(count // 10, 60)
                print(f"{hour:02d}:00–{hour:02d}:59 — {count:>4} {bar}")
        else:
            print("Временные метки отсутствуют или имеют неизвестный формат")

        print("\nIP-адреса, специализирующиеся на конкретном типе атак")
        print("----------------------------------------------------")

        specialists = self.specialized_ips()

        if specialists:
            for ip, main_attack, main_count, total_ip_attacks, share in specialists:
                print(
                    f"{ip:<15} — {main_attack:<18} "
                    f"{main_count}/{total_ip_attacks} атак ({share:.0%})"
                )
        else:
            print("Явной специализации не найдено")

        print("\nВложенный Counter по IP")
        print("----------------------")

        for ip, counter in self.source_ip_counter.most_common(10):
            print(f"{ip}: {dict(self.attacks_by_ip[ip].most_common())}")


def analyze_logs(
    logs: Iterable[LogRecord],
    rare_threshold: int = 5,
    specialization_threshold: float = 0.80,
    min_ip_attacks: int = 10,
) -> None:
    """Функция-обертка для запуска анализа."""
    analyzer = AttackAnalyzer(
        logs,
        rare_threshold=rare_threshold,
        specialization_threshold=specialization_threshold,
        min_ip_attacks=min_ip_attacks,
    )

    analyzer.analyze()
    analyzer.print_report()


def build_arg_parser() -> argparse.ArgumentParser:
    """Создает обработчик аргументов командной строки."""
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
    """Главная функция программы."""
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