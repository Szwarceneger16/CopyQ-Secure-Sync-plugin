// SPDX-License-Identifier: GPL-3.0-or-later
#include "signed_join_entry.h"
#include "device_identity_vault.h"
#include "device_key_envelope.h"
#include "key_reader.h"
#include "signed_join_checkpoint.h"
#include "signed_join_wizard.h"
#include "signed_tab_activation.h"
#include "storage.h"
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileInfo>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPointer>
#include <QScopeGuard>
#include <QStringList>
#include <algorithm>
#include <iterator>

namespace cqs::native {
namespace {
constexpr auto Caption = "Signed Join (experimental)";

[[noreturn]] void refuse() { throw trust::JournalError(trust::JournalCode::Enrollment); }

std::filesystem::path path(const QString &text) {
#ifdef Q_OS_WIN
    return std::filesystem::path(text.toStdWString());
#else
    return std::filesystem::u8path(text.toUtf8().toStdString());
#endif
}

Qt::CaseSensitivity pathCase() {
#ifdef Q_OS_WIN
    return Qt::CaseInsensitive;
#else
    return Qt::CaseSensitive;
#endif
}

QString checkedPath(const QString &text, bool directory) {
    const auto value = QDir::fromNativeSeparators(text);
    if (value.size() > 4096 || !QDir::isAbsolutePath(value) || value.startsWith(QStringLiteral("//")) ||
        value != QDir::cleanPath(value) || QDir(value).isRoot()) refuse();
    for (const auto c : value) if (c.unicode() < 32 || c.unicode() == 127) refuse();
    const QFileInfo info(value);
    const auto canonical = QDir::fromNativeSeparators(info.canonicalFilePath());
    if (canonical.isEmpty() || canonical.compare(value, pathCase()) != 0 ||
        (directory ? !info.isDir() : !info.isFile())) refuse();
    return canonical;
}

bool overlaps(const QString &a, const QString &b) {
    return a.compare(b, pathCase()) == 0 || a.startsWith(b + '/', pathCase()) ||
           b.startsWith(a + '/', pathCase());
}

QByteArray publicPin(const QString &text, qsizetype size) {
    const auto hex = text.toLatin1();
    if (hex.size() != 2 * size || !std::all_of(hex.begin(), hex.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    })) refuse();
    return QByteArray::fromHex(hex);
}

trust::Token nextToken(const QByteArray &bytes, qsizetype &offset) {
    trust::Token result{};
    std::copy_n(bytes.constData() + offset, result.size(), result.begin());
    offset += static_cast<qsizetype>(result.size());
    return result;
}

trust::Member nextMember(const QByteArray &bytes, qsizetype &offset) {
    return {nextToken(bytes, offset), nextToken(bytes, offset), nextToken(bytes, offset)};
}

struct Key {
    crypto::Bytes bytes;
    ~Key() { crypto::wipe(bytes); }
};

} // namespace

void openSignedJoinSetup(QWidget *parent, const QString &settingsFile, const Profile &legacy,
                         const std::function<bool()> &stillCurrent,
                         const ActivateSignedTab &activate,
                         const PrepareSignedReplica &prepareReplica) {
    const QPointer<QWidget> owner(parent);
    const QPointer<QDialog> dialog(new QDialog(parent));
    const auto close = qScopeGuard([dialog] { delete dialog.data(); });
    dialog->setObjectName(QStringLiteral("cqsSignedJoinSetup"));
    dialog->setWindowTitle(QString::fromLatin1(Caption));
    auto *form = new QFormLayout(dialog);
    auto *notice = new QLabel(QStringLiteral("Open separately provisioned signed Join storage. Enter pins from trusted "
        "local setup. Never take these pins from a certificate or from the synchronization folder. "
        "This workflow writes a separate encrypted checkpoint after explicit confirmation. "
        "Genesis pin order: group, founder ID, founder signing key, founder encryption key, public recovery "
        "binding, initial key commitment. Local pin order: device ID, signing key, encryption key."), dialog);
    notice->setTextFormat(Qt::PlainText);
    notice->setWordWrap(true);
    form->addRow(notice);
    auto field = [&](const QString &label, int limit = 4096) {
        auto *edit = new QLineEdit(dialog);
        edit->setMaxLength(limit + 1);
        form->addRow(label, edit);
        return edit;
    };
    auto *genesisInput = field(QStringLiteral("Genesis pins (384 hex digits)"), 384);
    auto *memberInput = field(QStringLiteral("Local identity pins (192 hex digits)"), 192);
    auto *vaultInput = field(QStringLiteral("Private identity vault folder"));
    auto *journalInput = field(QStringLiteral("Private trust journal folder"));
    auto *transportInput = field(QStringLiteral("Signed synchronization root"));
    auto *checkpointInput = field(QStringLiteral("Separate private checkpoint folder"));
    auto *vaultKeyInput = field(QStringLiteral("Identity vault key file"));
    auto *journalKeyInput = field(QStringLiteral("Trust journal key file"));
    auto *checkpointKeyInput = field(QStringLiteral("Checkpoint key file"));
    auto *publisherInput = field(QStringLiteral("Group key file (optional, for a publisher)"));
    auto *stagingInput = field(QStringLiteral("Private publication staging folder (Windows publisher only)"));
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Open | QDialogButtonBox::Cancel, dialog);
    QObject::connect(buttons, &QDialogButtonBox::accepted, dialog, &QDialog::accept);
    QObject::connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
    form->addRow(buttons);
    if (dialog->exec() != QDialog::Accepted || !dialog || !owner || !stillCurrent()) return;
    try {
        qsizetype offset = 0;
        const auto publicGenesis = publicPin(genesisInput->text(), 192);
        const trust::Genesis genesis{nextToken(publicGenesis, offset), nextMember(publicGenesis, offset),
                                     nextToken(publicGenesis, offset), nextToken(publicGenesis, offset)};
        offset = 0;
        const auto local = nextMember(publicPin(memberInput->text(), 96), offset);
        const auto vault = checkedPath(vaultInput->text(), true);
        const auto journalPath = checkedPath(journalInput->text(), true);
        const auto transportPath = checkedPath(transportInput->text(), true);
        const auto checkpointPath = checkedPath(checkpointInput->text(), true);
        const auto vaultKey = checkedPath(vaultKeyInput->text(), false);
        const auto journalKey = checkedPath(journalKeyInput->text(), false);
        const auto checkpointKey = checkedPath(checkpointKeyInput->text(), false);
        const auto publisherKey = publisherInput->text().isEmpty() ? QString{} : checkedPath(publisherInput->text(), false);
        const auto staging = stagingInput->text().isEmpty() ? QString{} : checkedPath(stagingInput->text(), true);
        const auto settings = checkedPath(settingsFile, false);
        const QStringList paths{vault, journalPath, transportPath, checkpointPath, vaultKey, journalKey,
                                checkpointKey, publisherKey, staging, settings};
        for (qsizetype i = 0; i < paths.size(); ++i) for (qsizetype j = i + 1; j < paths.size(); ++j)
            if (!paths[i].isEmpty() && !paths[j].isEmpty() && overlaps(paths[i], paths[j])) refuse();
        for (const auto &legacyPath : {legacy.stateDirectory, legacy.vaultDirectory, legacy.keyFile, legacy.transport})
            if (!legacyPath.isEmpty() && overlaps(checkpointPath, QDir::cleanPath(QDir::fromNativeSeparators(legacyPath))))
                refuse();
#ifndef Q_OS_WIN
        if (!staging.isEmpty()) refuse();
#endif
        dialog->hide();

        Key identityCredential{readKeyStrict(path(vaultKey))};
        Key journalCredential{readKeyStrict(path(journalKey))};
        Key checkpointCredential{readKeyStrict(path(checkpointKey))};
        Key publisherCredential{publisherKey.isEmpty() ? crypto::Bytes{} : readKeyStrict(path(publisherKey))};
        if (identityCredential.bytes == journalCredential.bytes || identityCredential.bytes == checkpointCredential.bytes ||
            journalCredential.bytes == checkpointCredential.bytes || publisherCredential.bytes == identityCredential.bytes ||
            publisherCredential.bytes == journalCredential.bytes || publisherCredential.bytes == checkpointCredential.bytes)
            refuse();
        const trust::Membership genesisState(genesis.group, genesis.founder, genesis.recovery, genesis.initialKeyCommitment);
        const auto identity = trust::IdentityVault::load(path(vault), {genesis.group, genesisState.current().root, local},
                                                         identityCredential.bytes);
        crypto::wipe(identityCredential.bytes);
        const auto journalBinding = trust::TrustJournal::binding(genesis, local);
        state::FileStore journalStore(path(journalPath), journalBinding, journalCredential.bytes);
        crypto::wipe(journalCredential.bytes);
        trust::TrustJournal journal(journalStore, genesis, local);
        const storage::Directory transport(path(transportPath));
        const auto binding = signedTabBinding(settings, checkpointPath, journalBinding);
        trust::SignedJoinCheckpoint checkpoint(path(checkpointPath), checkpointCredential.bytes, binding);
        crypto::wipe(checkpointCredential.bytes);
        const auto groupKey = publisherKey.isEmpty() ? nullptr : trust::SyncKey::import(publisherCredential.bytes);
        crypto::wipe(publisherCredential.bytes);
        if (owner && stillCurrent()) runSignedJoinWizard(owner, journal, *identity, transport, checkpoint, binding,
            groupKey.get(), path(staging), stillCurrent, [&](const trust::JoinActivation &expected) {
                return activate({checkpointPath, checkpointKey, expected}, journalBinding, {transportPath, journalPath});
            }, transportPath, [&] {
                return prepareReplica(checkpointPath, checkpointKey, journalBinding, {transportPath, journalPath});
            });
    } catch (const std::exception &) {
        if (owner) QMessageBox::warning(owner, QString::fromLatin1(Caption),
            QStringLiteral("Signed Join setup was refused. Check the trusted pins, private paths and credential files."));
    }
}
} // namespace cqs::native
