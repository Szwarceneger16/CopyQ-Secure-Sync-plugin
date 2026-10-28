// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "profile.h"
#include "ui_status.h"
#include <QWidget>
#include <functional>

class QLineEdit;
class QLabel;
class QPushButton;
class QCheckBox;
namespace cqs::native {
class SettingsWidget final : public QWidget {
    Q_OBJECT
public:
    // Injectable chooser keeps tests off the user's real filesystem/desktop.
    using Chooser = std::function<QString(QWidget *, const QString &, bool)>;
    explicit SettingsWidget(const Profile &profile, QWidget *parent = nullptr,
                            Chooser chooser = {});
    Profile profile() const;
    bool automaticEnabled() const;
    void setAutomaticEnabled(bool);
    void setProfile(const Profile &profile);
    void setBusy(bool busy);
    void setStatus(const QString &text);
    void setRuntimeStatus(const UiContext &, const UiStatus &, bool applied, bool available=true);
signals:
    void inspectRequested(cqs::native::Profile profile);
    void initializeStorageRequested(cqs::native::Profile profile);
    void vaultActionRequested(QString action);
    void operationRequested(QString action);
private:
    QLineEdit *device_, *transport_, *key_, *state_, *vault_, *staging_;
    QLabel *status_, *runtimeStatus_;
    QWidget *operations_;
    QPushButton *diagnostics_;
    QString diagnosticsText_;
    QPushButton *inspect_, *initialize_;
    QCheckBox *storage_, *automatic_;
    QWidget *fields_;
    Chooser chooser_;
    int schema_ = 3;
    Profile original_;
    QString predecessor_;
    void browse(QLineEdit *edit, bool file);
};
} // namespace cqs::native
