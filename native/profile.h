// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <QString>
#include <QMetaType>
#include <QSettings>
#include <QByteArray>

namespace cqs::native {
// Only configuration paths/identity. Neither K-SYNC bytes nor clipboard contents
// are ever written to CopyQ's settings by this object.
struct Profile {
    QString device;
    QString transport;
    QString keyFile;
    QString stateDirectory;
    int schema = 3;
    bool standaloneStorage = false;
    QString vaultDirectory;
    QString publicationStaging; // Optional Windows-only I/O path; not record identity.
    QString predecessorBinding; // Authenticated cache handover; empty for original profiles.
    bool operator==(const Profile &other) const;
    bool operator!=(const Profile &other) const { return !(*this == other); }
    bool isEmpty() const;
};

// QSettings is already inside CopyQ's Plugins/securesync group.
Profile loadProfile(const QSettings &settings);
void saveProfile(QSettings &settings, const Profile &profile);
QByteArray encodeProfile(const Profile &);
Profile decodeProfile(const QByteArray &);
// One settings value is the activation boundary; ordinary fields are never
// individually switched during a history/key transition.
void activateProfile(QSettings &, const Profile &);
// Empty return means valid. Validation is a preflight, NOT authorization for
// later I/O: the handle-based adapters must still validate at operation time.
QString validateProfile(const Profile &profile, bool checkExistingPaths);
} // namespace cqs::native

Q_DECLARE_METATYPE(cqs::native::Profile)
