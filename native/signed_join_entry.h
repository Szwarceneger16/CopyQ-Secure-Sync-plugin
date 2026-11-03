// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "profile.h"
#include <functional>
#include <string>

class QWidget;

namespace cqs::native {
struct SignedTabConfiguration;
void openSignedJoinSetup(QWidget *parent, const QString &settingsFile, const Profile &legacy,
                         const std::function<bool()> &stillCurrent,
                         const std::function<bool(const SignedTabConfiguration &, const std::string &)> &activate);
}
