// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <functional>
namespace cqs::native::vault_testing {
enum class Point { VaultCreated, RotationPrepared, DataRekeyed, RotationFinished, MigrationRekeyed };
extern std::function<void(Point)> hook;
}
