// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#ifndef CQS_STATE_TESTING
#error State hooks are test-only
#endif
#include <functional>
namespace cqs::state::testing {
enum class Point { ReadPinned, ReadComplete, StageSynced, StageLinked, BeforePublish, Published, DirectorySynced };
extern std::function<void(Point)> hook;
}
