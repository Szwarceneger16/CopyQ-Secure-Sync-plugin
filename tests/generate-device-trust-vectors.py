#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent public fixtures for the isolated membership model encoding.

Uses Python struct/hashlib only, never calls the C++ implementation. Print to
stdout for deliberate regeneration; no real keys or user files are read.
"""
import hashlib
import struct


def domain(value):
    return ("CopyQ-Secure-Sync-membership-" + value + "-model-v1").encode("ascii") + b"\0"


def token(value):
    return bytes([value]) * 32


proposal = (domain("intent") + struct.pack(">I", 1)
            + token(1) + token(2) + token(3)
            + struct.pack(">QQ", 7, 3) + token(13) + bytes([1])
            + token(4) + token(5) + token(6)
            + token(7) + token(8) + struct.pack(">QQ", 100, 1000))
approver = token(9) + token(10) + token(11)
verification = hashlib.sha256(domain("verification") + proposal + approver).digest()
approval = domain("approval") + proposal + approver + verification
certificate = (domain("certificate") + proposal + struct.pack(">I", 2)
               + token(9) + bytes([0xA1]) * 64 + token(12) + bytes([0xB2]) * 64)

print("// SPDX-License-Identifier: GPL-3.0-or-later")
print("// Generated independently by tests/generate-device-trust-vectors.py.")
print("// PUBLIC TEST DATA: signature-shaped bytes below are NOT real signatures.")
print("#pragma once\nnamespace cqs::trust::fixtures {")
for name, value in [("ProposalHex", proposal), ("ProposalDigestHex", hashlib.sha256(proposal).digest()),
                    ("VerificationHex", verification), ("ApprovalHex", approval),
                    ("CertificateHex", certificate)]:
    print(f"inline constexpr const char *{name} =")
    encoded = value.hex()
    for start in range(0, len(encoded), 96):
        print('    "' + encoded[start:start + 96] + '"')
    print("    ;")
print("} // namespace cqs::trust::fixtures")
