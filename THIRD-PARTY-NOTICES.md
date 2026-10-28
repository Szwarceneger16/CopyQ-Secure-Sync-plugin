# License and dependency notices

CopyQ Secure Sync is GPL-3.0-or-later. The complete license is `LICENSE`.
Native packages contain one Secure Sync module, installation helpers and
documentation. They do not redistribute a CopyQ executable, Qt, an OpenSSL DLL,
a Python interpreter, QCA or any test driver.

| Component | Use in distributed module | License / source |
| --- | --- | --- |
| CopyQ 17.0.0 | Public interface headers plus `itemwidget.cpp` and `mimetypes.cpp` support code | GPL-3.0-or-later; full notice in `COPYQ-LICENSE`; pinned source in `ci/toolchain.json` |
| zlib 1.3.1 | Static in the Windows module; system library on Linux | zlib license below; Windows also carries the upstream `ZLIB-NOTICE.txt` |
| Qt 6 | Dynamic dependency supplied by the selected CopyQ/runtime | Not bundled; Qt's GPL-compatible terms apply to the selected installation |
| OpenSSL 3 | Linux system/runtime `libcrypto` dependency | Not bundled; Apache-2.0, https://www.openssl.org/source/license.html |
| Windows CNG/Win32 | Windows system cryptography and filesystem APIs | Operating-system components; not redistributed |

GitHub release assets include a corresponding-source archive containing the
exact plugin, pinned CopyQ and pinned zlib source checkouts, with their licenses
and build instructions. Each preserves its shallow Git identity so the offline
CopyQ ABI/source checks can be reproduced. Build/test-only QCA, its OpenSSL test
backend, SDKs and optional historical host regression are not linked into the
distributed module. The source archive retains their build scripts for review.

## zlib license

Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler

This software is provided 'as-is', without any express or implied warranty. In
no event will the authors be held liable for any damages arising from the use
of this software.

Permission is granted to anyone to use this software for any purpose, including
commercial applications, and to alter it and redistribute it freely, subject to
the following restrictions:

1. The origin of this software must not be misrepresented; you must not claim
   that you wrote the original software. If you use this software in a product,
   an acknowledgment in the product documentation would be appreciated but is
   not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.
