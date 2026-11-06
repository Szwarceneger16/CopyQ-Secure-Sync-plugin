# Signed device qualification

The `Signed device qualification` workflow builds the signed feature explicitly
with `CQS_TEST_DEVICE_CRYPTO=ON` and `CQS_BUILD_SIGNED_JOIN=ON`. Its artifacts are
named experimental and are separate from the release promotion workflow.

The workflow requires the complete signed source tree. Before that feature is
present on `main`, it reports that signed qualification is not applicable. A
partial source tree fails this check. This bootstrap case does not qualify any
signed code.

## Merge and evidence order

1. Review and accept the dedicated CI/workflow change into `main`.
2. Bring that accepted harness into the signed feature branch and run its current
   commit through all signed jobs.
3. Review the feature and its current reports before making release claims.

A run using an unaccepted harness is implementation validation. It does not
establish that a dependent feature passed the accepted default-branch harness.
There is no repository approval manifest requiring a separate hash-only exception
for this workflow. Dependency pins remain exact and receive ordinary source
review together with their build behavior.

## Required evidence

Each signed job checks the actual CMake cache, the complete required CTest
inventory, and the JUnit results. Missing, duplicate, disabled, failed or skipped
required tests fail qualification. The required signed inventory includes the
two-profile fixture, signed history and checkpoint tests, native activation and
background scheduler tests, together with the platform storage tests.

Linux tests run offline and unprivileged in the pinned SDK container. Its signed
SDK compiles libsodium 1.0.22 from the exact commit in
[`ci/signed-toolchain.json`](../ci/signed-toolchain.json), runs upstream checks,
and links a position-independent static library. Windows builds the same source
with MSVC 2022 and its dynamic CRT configuration, and executes the storage tests
on fixed local NTFS. The experimental DLL artifact includes its tested libsodium
DLL and license. Flatpak builds and executes the signed suites inside the matching
KDE SDK with network access disabled during the build and tests.

Additional process acceptance starts two disposable CopyQ profiles using the
official CopyQ 17 application on Linux and Windows, and the installed application
on Flatpak. The report gate requires two-way delivery, restart, conflict and
encrypted-backup behavior, rejection of incomplete or altered history, and a
marker-only native cache. Test fixtures use synthetic data and locally generated
test credentials. The runner must fail when a platform cannot execute a required
scenario. Logs and artifacts must not contain real user clipboard contents or
credentials.

These jobs test separate application processes and profiles in disposable runner
environments. Physical two-device/cloud delivery, hardware power loss, production
performance and an independent security audit remain separate qualification
evidence. Successful module loading alone does not establish those properties.
