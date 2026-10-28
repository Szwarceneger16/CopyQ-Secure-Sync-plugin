// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstdlib>
#include <iostream>
// Unlike assert(), these checks also execute in Release/-DNDEBUG builds.
#define CHECK(...) do { if(!(__VA_ARGS__)) { std::cerr << "CHECK failed: " #__VA_ARGS__ << " at " << __FILE__ << ':' << __LINE__ << '\n'; std::abort(); } } while(false)
