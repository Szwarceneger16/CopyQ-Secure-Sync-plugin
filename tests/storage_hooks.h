// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#ifndef CQS_STORAGE_TESTING
#error Test hooks must never be enabled in a release build
#endif
#include <functional>
namespace cqs::storage::testing {
enum class Point { FilePinned, ReadChunk, ScanRead, ScanAuthenticated,
                   PublishWritten, PublishReady, PublishLinked };
extern std::function<void(Point)> hook;
}
