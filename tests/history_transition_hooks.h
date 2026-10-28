// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <functional>
namespace cqs::native::transition_testing {
enum class Point { JournalCreated, SourceSuspended, VaultCreated, EventReserved, EventDelivered, EventRecorded, StateCreated, Ready, JournalSealed, SourceVaultSuspended };
extern std::function<void(Point)> hook;
}
