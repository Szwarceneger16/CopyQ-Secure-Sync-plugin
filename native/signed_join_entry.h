// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "profile.h"
#include <functional>

class QWidget;

namespace cqs::native {
void openSignedJoinSetup(QWidget *parent, const QString &settingsFile, const Profile &legacy,
                         const std::function<bool()> &stillCurrent);
}
