// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <functional>
namespace cqs::native::testing {
enum class Point { ReadPinned, ReadComplete };
extern std::function<void(Point)> hook;
} // namespace cqs::native::testing
