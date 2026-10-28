# SPDX-License-Identifier: GPL-3.0-or-later
import unittest
import xml.etree.ElementTree as ET
from check_tests_loader import gate


class GateTests(unittest.TestCase):
    def test_complete_inventory(self):
        gate.check_inventory({'tests': [{'name': 'native-loader', 'command': ['loader']}]}, {'native-loader'})

    def test_missing_inventory(self):
        with self.assertRaises(ValueError):
            gate.check_inventory({'tests': []}, {'native-loader'})

    def test_disabled_inventory(self):
        with self.assertRaises(ValueError):
            gate.check_inventory({'tests': [{'name': 'native-loader', 'command': ['loader'],
                'properties': [{'name': 'DISABLED', 'value': True}]}]}, {'native-loader'})

    def test_command_missing(self):
        with self.assertRaises(ValueError):
            gate.check_inventory({'tests': [{'name': 'native-loader'}]}, {'native-loader'})

    def test_complete_results(self):
        gate.check_result(ET.fromstring('<testsuite><testcase name="native-loader" status="run"/></testsuite>'), {'native-loader'}, 'PASS loader')

    def test_missing_results(self):
        with self.assertRaises(ValueError):
            gate.check_result(ET.fromstring('<testsuite/>'), {'native-loader'}, '')

    def test_failed_skipped_notrun_results(self):
        for child in ('failure', 'error', 'skipped'):
            with self.subTest(child=child), self.assertRaises(ValueError):
                gate.check_result(ET.fromstring(f'<testsuite><testcase name="native-loader"><{child}/></testcase></testsuite>'), {'native-loader'}, '')
        with self.assertRaises(ValueError):
            gate.check_result(ET.fromstring('<testsuite><testcase name="native-loader" status="notrun"/></testsuite>'), {'native-loader'}, '')

    def test_subscenario_skip(self):
        for log in ('SKIP root symlink', '  8: SKIP record symlink'):
            with self.subTest(log=log), self.assertRaises(ValueError):
                gate.check_result(ET.fromstring('<testsuite><testcase name="state-windows"/></testsuite>'), {'state-windows'}, log)

    def test_all_os_contracts_include_native_module(self):
        for platform in ('linux', 'windows'):
            self.assertTrue({'native-unified-state', 'password-state', 'native-key-vault', 'native-loader', 'native-settings', 'native-model-clipboard', 'native-host-persistence', 'native-standalone-lab', 'native-standalone-storage', 'packed-items'} <= gate.expected(platform))
        self.assertIn('state-windows', gate.expected('windows'))
        self.assertIn('key-reader-windows', gate.expected('windows'))
        self.assertIn('storage-windows', gate.expected('windows'))
        self.assertIn('native-inspector', gate.expected('windows'))
        self.assertIn('native-inspector', gate.expected('linux'))
        self.assertIn('storage', gate.expected('linux'))


if __name__ == '__main__':
    unittest.main()
