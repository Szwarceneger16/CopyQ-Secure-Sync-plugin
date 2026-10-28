# SPDX-License-Identifier: GPL-3.0-or-later
[CmdletBinding()]
param([Parameter(Mandatory)][string]$CopyQSource,
      [Parameter(Mandatory)][string]$ZlibSource,
      [Parameter(Mandatory)][string]$QcaSource,
      [Parameter(Mandatory)][string]$OpenSSLSource,
      [Parameter(Mandatory)][string]$Out)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program exited with code $LASTEXITCODE" }
}
$Source = Split-Path $PSScriptRoot -Parent
$CopyQSource = (Resolve-Path -LiteralPath $CopyQSource).Path
$ZlibSource = (Resolve-Path -LiteralPath $ZlibSource).Path
$QcaSource = (Resolve-Path -LiteralPath $QcaSource).Path
$OpenSSLSource = (Resolve-Path -LiteralPath $OpenSSLSource).Path
$Out = [IO.Path]::GetFullPath($Out)
New-Item -ItemType Directory -Force -Path "$Out/reports", "$Out/stage" | Out-Null
Start-Transcript -Path "$Out/reports/build.log"
try {
    $lock = Get-Content -Raw "$PSScriptRoot/toolchain.json" | ConvertFrom-Json
    foreach ($pair in @(@($CopyQSource, $lock.copyq_commit), @($ZlibSource, $lock.zlib_commit), @($QcaSource, $lock.qca_commit), @($OpenSSLSource, $lock.openssl_commit))) {
        $actual = (& git -C $pair[0] rev-parse HEAD).Trim()
        if ($LASTEXITCODE -ne 0 -or $actual -ne $pair[1]) { throw 'Dependency commit mismatch' }
    }
    # Native tests MUST execute on a real local NTFS volume, not Wine or ntfs-3g.
    $testRoot = Join-Path $env:RUNNER_TEMP 'cqs-ntfs-tests'
    New-Item -ItemType Directory -Force -Path $testRoot | Out-Null
    $drive = [IO.Path]::GetPathRoot($testRoot).Substring(0, 1)
    $volume = Get-Volume -DriveLetter $drive
    $volume | Select-Object DriveLetter, FileSystem, DriveType, HealthStatus | Format-List
    if ($volume.FileSystem -ne 'NTFS' -or $volume.DriveType -ne 'Fixed') { throw 'Native tests require fixed NTFS' }
    $env:TEMP = $testRoot
    $env:TMP = $testRoot
    $env:QT_QPA_PLATFORM = 'offscreen'
    $env:GIT_OPTIONAL_LOCKS = '0'
    # Ephemeral GitHub VM only. Make symlink tests mandatory instead of SKIP->green.
    $developerMode = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock'
    New-Item -Path $developerMode -Force | Out-Null
    New-ItemProperty -Path $developerMode -Name AllowDevelopmentWithoutDevLicense -Value 1 -PropertyType DWord -Force | Out-Null
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $vs = (& $vswhere -latest -version '[17.0,18.0)' -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath).Trim()
    if (-not $vs) { throw 'Visual Studio 2022 C++ tools missing' }
    Import-Module "$vs/Common7/Tools/Microsoft.VisualStudio.DevShell.dll"
    Enter-VsDevShell -VsInstallPath $vs -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'
    Invoke-Checked python @('-m', 'venv', "$Out/aqt-venv")
    $py = "$Out/aqt-venv/Scripts/python.exe"
    Invoke-Checked $py @('-m', 'pip', 'install', '--disable-pip-version-check', "aqtinstall==$($lock.aqtinstall)")
    Invoke-Checked $py @('-m', 'aqt', 'install-qt', 'windows', 'desktop', $lock.qt, 'win64_msvc2022_64', '--outputdir', "$Out/Qt", '--archives', 'qtbase', 'qt5compat', '--modules', 'qt5compat')
    $qt = "$Out/Qt/$($lock.qt)/msvc2022_64"
    if (-not (Test-Path "$qt/lib/cmake/Qt6/Qt6Config.cmake")) { throw 'Qt SDK incomplete' }
    $env:PATH = "$qt/bin;$env:PATH"
    # Preserve CMake/MSVC defaults. Setting CMAKE_CXX_FLAGS=/utf-8 discarded
    # /EHsc, so exceptions bypassed destructors and left leases/mutexes held.
    $env:CXXFLAGS = "$env:CXXFLAGS /utf-8 /EHsc /we4530"
    Invoke-Checked cmake @('--version')
    Invoke-Checked "$qt/bin/qmake.exe" @('-query', 'QT_VERSION')
    # Real QCA/OpenSSL host encryption; built with the same MSVC/CRT and Qt SDK.
    # CopyQ's DEK stays in the host. These libraries are test SDK dependencies,
    # not linked/bundled into the standalone transport plugin.
    New-Item -ItemType Directory -Force -Path "$Out/openssl-build" | Out-Null
    Push-Location "$Out/openssl-build"
    try {
        Invoke-Checked perl @("$OpenSSLSource/Configure", 'VC-WIN64A', 'no-asm', 'no-tests', 'shared', "--prefix=$Out/openssl", '--openssldir=ssl')
        Invoke-Checked nmake @('/NOLOGO')
        Invoke-Checked nmake @('/NOLOGO', 'install_sw')
    } finally { Pop-Location }
    $env:PATH = "$Out/openssl/bin;$env:PATH"
    Invoke-Checked cmake @('-S', $QcaSource, '-B', "$Out/qca-build", '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release', "-DCMAKE_PREFIX_PATH=$qt", "-DOPENSSL_ROOT_DIR=$Out/openssl", "-DCMAKE_INSTALL_PREFIX=$Out/qca", '-DBUILD_WITH_QT6=ON', '-DBUILD_TESTS=OFF', '-DBUILD_TOOLS=OFF', '-DBUILD_PLUGINS=ossl')
    Invoke-Checked cmake @('--build', "$Out/qca-build", '--parallel', '2')
    Invoke-Checked cmake @('--install', "$Out/qca-build")
    $env:PATH = "$Out/qca/bin;$env:PATH"
    $env:QCA_PLUGIN_PATH = "$Out/qca/lib/qca-qt6"
    # Build static zlib with the SAME MSVC/CRT as the module; do not borrow MinGW libraries.
    Invoke-Checked cmake @('-S', $ZlibSource, '-B', "$Out/zlib-build", '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release', "-DCMAKE_INSTALL_PREFIX=$Out/zlib", '-DZLIB_BUILD_EXAMPLES=OFF')
    Invoke-Checked cmake @('--build', "$Out/zlib-build", '--parallel', '2')
    Invoke-Checked cmake @('--install', "$Out/zlib-build")
    Invoke-Checked cmake @('-S', $Source, '-B', "$Out/build", '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release', '-DBUILD_TESTING=ON', '-DCQS_BUILD_NATIVE_PLUGIN=ON', '-DCQS_BUILD_UI_TEST_PLUGIN=ON', '-DCQS_BUILD_STANDALONE_LAB=ON', '-DCQS_TEST_LEGACY_HOST_BRIDGE=ON', "-DCOPYQ_SOURCE_DIR=$CopyQSource", "-DCMAKE_PREFIX_PATH=$qt;$Out/qca", "-DZLIB_ROOT=$Out/zlib", '-DZLIB_USE_STATIC_LIBS=ON', "-DCMAKE_INSTALL_PREFIX=$Out/stage")
    Invoke-Checked cmake @('--build', "$Out/build", '--parallel', '2')
    Invoke-Checked python @("$PSScriptRoot/check-tests.py", "$Out/build", 'windows', '--inventory-only')
    Invoke-Checked ctest @('--test-dir', "$Out/build", '-C', 'Release', '--parallel', '2', '--output-on-failure', '--output-junit', "$Out/reports/ctest.xml")
    Invoke-Checked python @("$PSScriptRoot/check-tests.py", "$Out/build", 'windows', '--junit', "$Out/reports/ctest.xml")
    Invoke-Checked cmake @('--install', "$Out/build")
    Invoke-Checked "$Out/build/cqs-loader-test.exe" @("$Out/stage/copyq/plugins/securesync.dll")
    Invoke-Checked dumpbin @('/DEPENDENTS', "$Out/stage/copyq/plugins/securesync.dll")
    Invoke-Checked python @("$PSScriptRoot/package.py", '--platform', 'windows-x86_64', '--source', $Source, '--copyq', $CopyQSource, '--zlib', $ZlibSource, '--out', $Out)
} finally {
    Stop-Transcript
}
