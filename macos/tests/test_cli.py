# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline checks only: never invoke the root networking path."""
import subprocess
import sys
import unittest

CLIENT = sys.argv.pop(1)


class ConfigurationTests(unittest.TestCase):
    base = ["--server", "192.0.2.1", "--mac", "02:11:22:33:44:55", "--route", "203.0.113.0/24"]

    def run_config(self, arguments, code):
        result = subprocess.run([CLIENT, *arguments, "--check-config"], capture_output=True, text=True)
        self.assertEqual(result.returncode, code, result.stderr)
        return result.stdout

    def test_valid(self):
        self.run_config(self.base, 0)
        for port in ["0", "1", "65534", "65535"]:
            self.run_config([*self.base, "--port", port, "--seed", "255", "--sproxy"], 0)

    def test_default_route_is_split(self):
        out = self.run_config([*self.base[:-2], "--route", "0.0.0.0/0"], 0)
        self.assertIn("routes=2", out)

    def test_invalid(self):
        for arguments in [[], self.base[:-2], [*self.base, "extra"],
                          [*self.base, "--port", "65536"], [*self.base, "--port", "-1"],
                          [*self.base, "--seed", "256"], [*self.base, "--mtu", "575"],
                          [*self.base, "--user-hash", "4294967296"],
                          [*self.base, "--mac", "01:00:00:00:00:01"],
                          [*self.base, "--mac", "00:00:00:00:00:00"],
                          [*self.base, "--mac", "02:11:22:33:44:zz"],
                          [*self.base, "--server", "example.com"],
                          [*self.base, "--server", "127.0.0.1"],
                          [*self.base, "--route", "203.0.113.1/24"],
                          [*self.base, "--route", "192.0.2.1/32"],
                          [*self.base, "--route", "203.0.113.0/24"]]:
            with self.subTest(arguments=arguments):
                self.run_config(arguments, 2)


if __name__ == "__main__":
    unittest.main()
