// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "device_join.h"
#include <optional>

class QWidget;

namespace cqs::native {
// Call on the GUI thread with a fresh review produced by the local journal.
// The caller must revalidate the proposal and its deadline before committing.
void showDeviceJoinReview(QWidget *parent, const trust::JoinReview &review);
std::optional<std::vector<trust::JoinConfirmation>>
confirmDeviceJoinReview(QWidget *parent, const trust::JoinReview &review);
} // namespace cqs::native
