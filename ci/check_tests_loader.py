# SPDX-License-Identifier: GPL-3.0-or-later
import importlib.util
from pathlib import Path
spec = importlib.util.spec_from_file_location('cqs_test_gate', Path(__file__).with_name('check-tests.py'))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
