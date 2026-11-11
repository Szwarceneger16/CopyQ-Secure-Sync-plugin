// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "signed_setup.h"
#include <functional>
#include <memory>

class QWidget;

namespace cqs::native {
// Returns an unlocked, authenticated local setup. The caller owns its guarded
// secrets and may retain it only for an explicitly enabled in-memory session.
std::unique_ptr<trust::SignedSetup> openSignedSetupWizard(QWidget *parent,
    const std::function<bool()> &stillCurrent = {}, const trust::SignedSetup::PathValidator &validatePaths = {});
} // namespace cqs::native
