// SPDX-License-Identifier: GPL-3.0-or-later
#include "settings_widget.h"
#include <QDir>
#include <QCheckBox>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QTabWidget>
#include <QScrollArea>
#include <QApplication>
#include <QClipboard>
#include <utility>

namespace cqs::native {
SettingsWidget::SettingsWidget(const Profile &p, QWidget *parent, Chooser chooser)
    : QWidget(parent), chooser_(std::move(chooser)) {
    setObjectName(QStringLiteral("cqsSettings"));
    auto *layout = new QVBoxLayout(this);
    runtimeStatus_=new QLabel(this);runtimeStatus_->setObjectName("cqsRuntimeStatus");
    runtimeStatus_->setWordWrap(true);runtimeStatus_->setTextFormat(Qt::PlainText);
    runtimeStatus_->setTextInteractionFlags(Qt::TextSelectableByMouse);layout->addWidget(runtimeStatus_);
    diagnostics_=new QPushButton(tr("Copy safe diagnostics"),this);diagnostics_->setObjectName("cqsCopyDiagnostics");
    diagnostics_->setToolTip(tr("Copies only state codes and boolean flags. Excludes paths, device/event IDs, keys, passwords and clipboard contents."));
    layout->addWidget(diagnostics_);connect(diagnostics_,&QPushButton::clicked,this,[this]{QApplication::clipboard()->setText(diagnosticsText_);});
    auto *tabs=new QTabWidget(this);tabs->setObjectName("cqsSettingsTabs");layout->addWidget(tabs);
    auto *configuration=new QWidget(tabs);auto *configurationLayout=new QVBoxLayout(configuration);
    auto *intro = new QLabel(tr("Configure Secure Sync, then apply the settings before running device or recovery actions. "
        "The synchronized tab is synced_tray. Seed is for the first device; Join connects a later device."), configuration);
    intro->setTextFormat(Qt::PlainText); intro->setWordWrap(true); configurationLayout->addWidget(intro);
    fields_ = new QWidget(this);
    auto *form = new QFormLayout(fields_);
    auto *tab = new QLineEdit(QStringLiteral("synced_tray"), fields_);
    tab->setReadOnly(true); tab->setObjectName(QStringLiteral("cqsTab"));
    form->addRow(tr("Synchronized tab (protocol v1):"), tab);
    device_ = new QLineEdit(fields_); device_->setMaxLength(32); device_->setObjectName(QStringLiteral("cqsDevice"));
    form->addRow(tr("Device ID:"), device_);
    auto pathRow = [this, form](const QString &label, const QString &name, bool file) {
        auto *row = new QWidget(fields_); auto *box = new QHBoxLayout(row); box->setContentsMargins(0,0,0,0);
        auto *edit = new QLineEdit(row); edit->setMaxLength(4096); edit->setObjectName(name); box->addWidget(edit);
        auto *button = new QPushButton(tr("Browse…"), row); button->setObjectName(name + QStringLiteral("Browse"));
        box->addWidget(button); form->addRow(label, row);
        connect(button, &QPushButton::clicked, this, [this, edit, file] { browse(edit, file); });
        return edit;
    };
    transport_ = pathRow(tr("Synchronization folder:"), QStringLiteral("cqsTransport"), false);
    key_ = pathRow(tr("Existing K-SYNC import (optional with vault):"), QStringLiteral("cqsKey"), true);
    vault_ = pathRow(tr("Private password-protected key vault:"), QStringLiteral("cqsVault"), false);
    state_ = pathRow(tr("Private state folder:"), QStringLiteral("cqsState"), false);
    staging_=pathRow(tr("Private publication staging folder (Windows, optional):"),QStringLiteral("cqsPublicationStaging"),false);
    staging_->setToolTip(tr("Windows: choose an existing private folder outside Nextcloud, on the same fixed NTFS volume as the synchronization folder. "
        "Leave empty to use the private state folder. Linux uses anonymous staging and does not use this folder."));
    state_->setToolTip(tr("Inspection does not read or write state here. Standalone storage uses this dedicated folder. "
        "Choose a private folder outside Nextcloud, not the folder containing your clipboard history."));
    configurationLayout->addWidget(fields_);
    storage_ = new QCheckBox(tr("Use independent encrypted storage for synced_tray (experimental)"), fields_);
    storage_->setObjectName(QStringLiteral("cqsStandaloneStorage"));
    form->addRow(storage_);
    automatic_=new QCheckBox(tr("Synchronize automatically after unlocking Secure Sync"),fields_);
    automatic_->setObjectName("cqsAutomaticSync");form->addRow(automatic_);
    automatic_->setToolTip(tr("Remember this choice across restarts. No password is saved. Active editors defer incoming changes."));
    auto *help = new QLabel(tr("The transport is a local folder containing events/. Nextcloud or Syncthing handles the network. "
        "K-SYNC and private state stay outside that folder. Browse/Cancel never changes existing files. "
        "CopyQ's OK/Apply saves only these paths and the device ID; it does not replace encryption keys."), this);
    help->setWordWrap(true); help->setTextFormat(Qt::PlainText); configurationLayout->addWidget(help);
    inspect_ = new QPushButton(tr("Inspect selected transport (read only)"), this);
    inspect_->setObjectName(QStringLiteral("cqsInspect")); configurationLayout->addWidget(inspect_);
    initialize_ = new QPushButton(tr("Initialize empty standalone storage…"), this);
    initialize_->setObjectName(QStringLiteral("cqsInitializeStorage")); configurationLayout->addWidget(initialize_);
    auto *storageHelp = new QLabel(tr("Standalone storage requires explicit initialization, a dedicated private folder and a new empty synced_tray tab. "
        "Preserve an ordinary tab first, then use the guarded import command. Supported data: binary MIME, up to 10,000 items and 32 MiB, with an additional packed-data limit. "
        "Local and shared keys are protected by a separate Secure Sync password. CopyQ has its own password. "
        "Run Secure Sync: finish encrypted removal from CopyQ's command menu before disabling this plugin; it requires Encrypt Tabs. "
        "Preserved CopyQ file-backed values can be imported with the guarded migration action; the source is kept."), this);
    storageHelp->setWordWrap(true); storageHelp->setTextFormat(Qt::PlainText); configurationLayout->addWidget(storageHelp);
    auto page=[tabs](QWidget *content,const QString &title){auto *scroll=new QScrollArea(tabs);scroll->setWidgetResizable(true);scroll->setWidget(content);tabs->addTab(scroll,title);};
    page(configuration,tr("Configuration"));
    operations_=new QWidget(tabs);auto *operationLayout=new QVBoxLayout(operations_);
    auto *operationHelp=new QLabel(tr("Actions use the applied profile and CopyQ's standard commands. They checkpoint and ordinarily unload the tab when required. "
        "Close editors first. Destructive decisions require confirmation. Changes made here take effect immediately; Cancel in CopyQ preferences does not undo completed actions."),operations_);
    operationHelp->setWordWrap(true);operationHelp->setTextFormat(Qt::PlainText);operationLayout->addWidget(operationHelp);
    for(const auto &entry:uiActions()){
        auto *button=new QPushButton(uiText(entry.label),operations_);button->setObjectName("cqsOperation_"+QLatin1String(entry.id));
        operationLayout->addWidget(button);connect(button,&QPushButton::clicked,this,[this,id=QString::fromLatin1(entry.id)]{emit operationRequested(id);});
    }
    page(operations_,tr("Devices and recovery"));
    auto *actions = new QWidget(tabs); auto *actionLayout = new QVBoxLayout(actions);
    const QList<QPair<QString, QString>> vaultActions{
        {"unlockStorage", tr("Unlock Secure Sync…")}, {"lockStorage", tr("Lock Secure Sync (close editors and switch tab first)")},
        {"changeStoragePassword", tr("Change Secure Sync password…")}, {"rotateLocalKey", tr("Rotate local data key / finish interrupted rotation…")},
        {"backupVault", tr("Back up encrypted keys…")}, {"restoreMissingVault", tr("Restore missing key vault…")}, {"repairMissingVault", tr("Rebuild a missing vault from currently unlocked keys…")},
        {"exportSyncKey", tr("Share encrypted synchronization key…")}, {"importSyncKey", tr("Set up from a shared encrypted key…")},
        {"resumeStorageSetup", tr("Finish interrupted initial setup…")}, {"migrateLegacyStorage", tr("Migrate earlier experimental local storage…")},
        {"prepareDetach", tr("Removal instructions (use CopyQ command menu)")},
        {"finishDetach", tr("Confirm completed CopyQ handoff (or run Secure Sync: finish encrypted removal)")},
        {"cancelDetach", tr("Cancel pending removal…")}};
    for (const auto &entry : vaultActions) {
        auto *button = new QPushButton(entry.second, actions); button->setObjectName(QStringLiteral("cqsVaultAction_") + entry.first);
        actionLayout->addWidget(button); connect(button, &QPushButton::clicked, this, [this, action=entry.first]{emit vaultActionRequested(action);});
    }
    page(actions,tr("Keys and removal"));
    status_ = new QLabel(this); status_->setObjectName(QStringLiteral("cqsStatus"));
    status_->setWordWrap(true); status_->setTextFormat(Qt::PlainText);
    status_->setTextInteractionFlags(Qt::TextSelectableByMouse); layout->addWidget(status_); layout->addStretch();
    connect(inspect_, &QPushButton::clicked, this, [this] {
        const auto value = profile();
        auto paths=value;if(!paths.vaultDirectory.isEmpty())paths.keyFile.clear();
        const auto structural=validateProfile(value,false);
        const auto error=structural.isEmpty()?validateProfile(paths,true):structural;
        if (!error.isEmpty()) { setStatus(error); return; }
        emit inspectRequested(value);
    });
    connect(initialize_, &QPushButton::clicked, this, [this] {
        const auto value = profile(); const auto error = validateProfile(value, true);
        if (!value.standaloneStorage || !error.isEmpty()) {
            setStatus(error.isEmpty() ? tr("Select standalone storage before explicit initialization.") : error); return;
        }
        emit initializeStorageRequested(value);
    });
    setProfile(p);
    setStatus(tr("Transport not inspected. Inspection is read only and does not accept history."));
    setRuntimeStatus({},presentStatus({}),false);
}
void SettingsWidget::browse(QLineEdit *edit, bool file) {
    const auto before = edit->text();
    QString selected;
    if (chooser_) selected = chooser_(this, before, file);
    else if (file) selected = QFileDialog::getOpenFileName(this, tr("Choose existing K-SYNC file"), before,
                    tr("Key files (*.key);;All files (*)"), nullptr, QFileDialog::DontResolveSymlinks);
    else selected = QFileDialog::getExistingDirectory(this, tr("Choose existing local folder"), before,
                    QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (!selected.isEmpty()) edit->setText(QDir::fromNativeSeparators(selected));
}
bool SettingsWidget::automaticEnabled() const{return automatic_->isChecked();}
void SettingsWidget::setAutomaticEnabled(bool enabled){automatic_->setChecked(enabled);}
Profile SettingsWidget::profile() const {
    // Preserve QString's original null marker when visible text is unchanged:
    // legacy authenticated bindings distinguish a null path from an empty one.
    const auto text=[](const QLineEdit *edit,const QString &original){const auto value=edit->text();return value==original?original:value;};
    return {text(device_,original_.device),text(transport_,original_.transport),text(key_,original_.keyFile),text(state_,original_.stateDirectory),
        schema_ == 2 && !vault_->text().isEmpty() ? 3 : schema_,storage_->isChecked(),text(vault_,original_.vaultDirectory),text(staging_,original_.publicationStaging),predecessor_};
}
void SettingsWidget::setProfile(const Profile &p) {
    original_=p;
    schema_ = p.schema;
    predecessor_=p.predecessorBinding;
    device_->setText(p.device); transport_->setText(p.transport); key_->setText(p.keyFile); state_->setText(p.stateDirectory);
    storage_->setChecked(p.standaloneStorage);
    vault_->setText(p.vaultDirectory);
    staging_->setText(p.publicationStaging);
}
void SettingsWidget::setBusy(bool busy) { fields_->setEnabled(!busy); inspect_->setEnabled(!busy); initialize_->setEnabled(!busy); }
void SettingsWidget::setStatus(const QString &text) { status_->setText(text); }
void SettingsWidget::setRuntimeStatus(const UiContext &context,const UiStatus &status,bool applied,bool available) {
    runtimeStatus_->setText(status.text()+(applied?QString{}:tr("\nApply the current profile before device, key or recovery actions.")));
    diagnosticsText_=status.diagnostic(context);
    for(auto *button:operations_->findChildren<QPushButton *>())
        button->setEnabled(applied&&available&&context.enabled&&(!context.busy||button->objectName()=="cqsOperation_stopAutomaticSync"));
    for(auto *button:findChildren<QPushButton *>())if(button->objectName().startsWith("cqsVaultAction_"))button->setEnabled(applied&&available&&context.enabled&&!context.busy);
}
} // namespace cqs::native
