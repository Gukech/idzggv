import unittest

from mainsc import AttackAnalyzer, parse_timestamp


class TestAttackAnalyzer(unittest.TestCase):
    def setUp(self) -> None:
        self.logs = [
            {
                "timestamp": "2026-06-16 00:01:00",
                "attack_type": "DDoS",
                "source_ip": "10.0.0.1",
                "target_port": "80",
            },
            {
                "timestamp": "2026-06-16 00:10:00",
                "attack_type": "DDoS",
                "source_ip": "10.0.0.1",
                "target_port": "80",
            },
            {
                "timestamp": "2026-06-16 01:00:00",
                "attack_type": "DDoS",
                "source_ip": "10.0.0.1",
                "target_port": "80",
            },
            {
                "timestamp": "2026-06-16 01:20:00",
                "attack_type": "DDoS",
                "source_ip": "10.0.0.1",
                "target_port": "80",
            },
            {
                "timestamp": "2026-06-16 02:00:00",
                "attack_type": "SQL Injection",
                "source_ip": "10.0.0.2",
                "target_port": "443",
            },
            {
                "timestamp": "2026-06-16 03:15:00",
                "attack_type": "SQL Injection",
                "source_ip": "10.0.0.2",
                "target_port": "443",
            },
            {
                "timestamp": "2026-06-16 03:25:00",
                "attack_type": "XSS",
                "source_ip": "10.0.0.3",
                "target_port": "22",
            },
            {
                "timestamp": "2026-06-16 04:00:00",
                "attack_type": "Port Scan",
                "source_ip": "10.0.0.2",
                "target_port": "22",
            },
        ]

        self.analyzer = AttackAnalyzer(
            self.logs,
            rare_threshold=2,
            specialization_threshold=0.75,
            min_ip_attacks=3,
        )
        self.analyzer.analyze()

    def test_total_records(self) -> None:
        self.assertEqual(self.analyzer.total_records, 8)

    def test_top_attack_types(self) -> None:
        self.assertEqual(
            self.analyzer.top_attack_types(2),
            [("DDoS", 4), ("SQL Injection", 2)],
        )

    def test_top_source_ips(self) -> None:
        self.assertEqual(
            self.analyzer.top_source_ips(2),
            [("10.0.0.1", 4), ("10.0.0.2", 3)],
        )

    def test_top_target_ports(self) -> None:
        self.assertEqual(
            self.analyzer.top_target_ports(3),
            [("80", 4), ("443", 2), ("22", 2)],
        )

    def test_rare_attacks(self) -> None:
        rare = self.analyzer.rare_attacks()

        self.assertEqual(rare["XSS"], 1)
        self.assertEqual(rare["Port Scan"], 1)
        self.assertNotIn("DDoS", rare)

    def test_attacks_by_hour(self) -> None:
        self.assertEqual(self.analyzer.attacks_by_hour[0], 2)
        self.assertEqual(self.analyzer.attacks_by_hour[1], 2)
        self.assertEqual(self.analyzer.attacks_by_hour[2], 1)
        self.assertEqual(self.analyzer.attacks_by_hour[3], 2)
        self.assertEqual(self.analyzer.attacks_by_hour[4], 1)

    def test_specialized_ips(self) -> None:
        specialists = self.analyzer.specialized_ips()

        self.assertEqual(len(specialists), 1)

        ip, main_attack, main_count, total_attacks, share = specialists[0]

        self.assertEqual(ip, "10.0.0.1")
        self.assertEqual(main_attack, "DDoS")
        self.assertEqual(main_count, 4)
        self.assertEqual(total_attacks, 4)
        self.assertEqual(share, 1.0)

    def test_nested_counter_by_ip(self) -> None:
        self.assertEqual(self.analyzer.attacks_by_ip["10.0.0.1"]["DDoS"], 4)
        self.assertEqual(self.analyzer.attacks_by_ip["10.0.0.2"]["SQL Injection"], 2)
        self.assertEqual(self.analyzer.attacks_by_ip["10.0.0.2"]["Port Scan"], 1)

    def test_parse_timestamp(self) -> None:
        timestamp = parse_timestamp("2026-06-16 13:45:00")

        self.assertIsNotNone(timestamp)
        self.assertEqual(timestamp.hour, 13)


if __name__ == "__main__":
    unittest.main()