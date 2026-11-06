// SPDX-License-Identifier: GPL-3.0-or-later
#include "signed_generation_wizard.h"
#include "signed_generation_transition.h"
#include "signed_setup.h"
#include <QDateTime>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QSettings>
#include <future>
#include <algorithm>

namespace cqs::native {
namespace {
constexpr auto Pending = "signed_generation_destination";
std::filesystem::path path(const QString &value) {
#ifdef Q_OS_WIN
    return std::filesystem::path(value.toStdWString());
#else
    return std::filesystem::u8path(value.toUtf8().toStdString());
#endif
}
QString text(const std::filesystem::path &value) {
#ifdef Q_OS_WIN
    return QString::fromStdWString(value.wstring());
#else
    const auto encoded = value.u8string();
    return QString::fromUtf8(encoded.data(), qsizetype(encoded.size()));
#endif
}
std::uint64_t now() {
    const auto seconds = QDateTime::currentSecsSinceEpoch();
    if (seconds <= 0) throw trust::JournalError(trust::JournalCode::ClockRollback);
    return static_cast<std::uint64_t>(seconds);
}
QString hex(const trust::Token &token) {
    return QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(token.data()), token.size()).toHex());
}
Qt::CaseSensitivity pathCase() {
#ifdef Q_OS_WIN
    return Qt::CaseInsensitive;
#else
    return Qt::CaseSensitive;
#endif
}
bool inside(const QString &value, const QString &parent) {
    return value.compare(parent, pathCase()) == 0 || value.startsWith(parent + '/', pathCase());
}
QString checkedDirectory(const QString &value) {
    const auto normalized = QDir::fromNativeSeparators(value);
    const auto canonical = QDir::fromNativeSeparators(QFileInfo(normalized).canonicalFilePath());
    if (normalized.size() > 4096 || !QDir::isAbsolutePath(normalized) || QDir(normalized).isRoot() ||
        normalized.startsWith(QStringLiteral("//")) || normalized != QDir::cleanPath(normalized) ||
        canonical.isEmpty() || normalized.compare(canonical, pathCase()) != 0 || !QFileInfo(canonical).isDir())
        throw trust::JournalError(trust::JournalCode::Enrollment);
    for (const auto character : normalized)
        if (character.unicode() < 32 || character.unicode() == 127)
            throw trust::JournalError(trust::JournalCode::Enrollment);
    return canonical;
}
}

bool runSignedGenerationWizard(QWidget *parent, trust::TrustJournal &journal, const trust::Identity &identity,
    const storage::Directory &transport, trust::SignedJoinCheckpoint &source, const crypto::Bytes &credential,
    const QString &settingsFile, const std::string &journalBinding, const SignedReplicaSource &replicaSource,
    const SignedReplicaRequest &request, const std::filesystem::path &privateStaging,
    const std::function<bool()> &stillCurrent, const std::function<bool(const QString &)> &validateDestination) {
    const auto check = [&] {
        if ((stillCurrent && !stillCurrent()) || !request.sourcePinned || !request.confirmSource || !request.confirmSource())
            throw trust::JournalError(trust::JournalCode::Enrollment);
    };
    check();
    QSettings settings(settingsFile, QSettings::IniFormat);
    settings.beginGroup("Plugins/securesync");
    const auto activeBytes = settings.value(SignedTabSetting).toByteArray();
    const auto current = decodeSignedTab(settingsFile, activeBytes);
    if (!current || current->expected.profileBinding != request.expected.profileBinding)
        throw trust::JournalError(trust::JournalCode::HistoryChanged);
    const auto validatePath = [&](const QString &value, bool parentSelection) {
        const auto canonical = checkedDirectory(value);
        QStringList excluded{replicaSource.transport, replicaSource.journal, current->checkpointDirectory,
            current->keyFile, settingsFile, text(privateStaging)};
        if (!replicaSource.setupRoot.isEmpty()) {
            const QDir root(checkedDirectory(replicaSource.setupRoot));
            for (const auto &child : {"identity", "journal", "checkpoint", "staging", "record-v1.cqr"})
                excluded.push_back(root.filePath(QString::fromLatin1(child)));
        }
        for (const auto &excludedPath : excluded) {
            if (excludedPath.isEmpty()) continue;
            const auto normalized = QDir::cleanPath(QDir::fromNativeSeparators(QFileInfo(excludedPath).absoluteFilePath()));
            const auto existing = QDir::fromNativeSeparators(QFileInfo(excludedPath).canonicalFilePath());
            for (const auto &protectedPath : {normalized, existing}) {
                if (!protectedPath.isEmpty() && (inside(canonical, protectedPath) ||
                    (!parentSelection && inside(protectedPath, canonical))))
                    throw trust::JournalError(trust::JournalCode::Enrollment);
            }
        }
        if (!parentSelection && validateDestination && !validateDestination(canonical))
            throw trust::JournalError(trust::JournalCode::Enrollment);
        return canonical;
    };
    QString destination;
    const auto pendingBytes = settings.value(Pending).toByteArray();
    if (!pendingBytes.isEmpty() && pendingBytes.size() <= 16 * 1024) {
        const auto pending = QJsonDocument::fromJson(pendingBytes).object();
        if (pending.value("active").toString().toLatin1() == activeBytes.toBase64())
            destination = pending.value("destination").toString();
    }
    if (!destination.isEmpty()) {
        const auto action = QMessageBox::question(parent, QObject::tr("Secure Sync — resume generation activation"),
            QObject::tr("Resume the prepared encrypted destination? Choose No to create another destination while retaining the earlier one."),
            QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel, QMessageBox::Yes);
        if (action == QMessageBox::Cancel) return false;
        if (action == QMessageBox::No) destination.clear();
    }
    if (destination.isEmpty()) {
        const auto chosen = QFileDialog::getExistingDirectory(parent, QObject::tr("Choose a private parent for the new generation"),
            replicaSource.setupRoot.isEmpty() ? QFileInfo(current->checkpointDirectory).absolutePath() : replicaSource.setupRoot,
            QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
        if (chosen.isEmpty()) return false;
        check();
        const auto selectedParent = validatePath(chosen, true);
        destination = std::async(std::launch::async, [&] { return text(trust::SignedSetup::createPrivateRoot(path(selectedParent))); }).get();
        destination = validatePath(destination, false);
    }
    destination = validatePath(destination, false);
    const auto binding = signedTabBinding(QFileInfo(settingsFile).canonicalFilePath(), destination, journalBinding);
    const auto review = std::async(std::launch::async, [&] {
        return trust::SignedGenerationTransition::review(journal, identity, transport, source, request.expected, binding, now(), true);
    }).get();
    check();
    settings.setValue(Pending, QJsonDocument(QJsonObject{
        {"active", QString::fromLatin1(activeBytes.toBase64())}, {"destination", destination}
    }).toJson(QJsonDocument::Compact));
    settings.sync();
    if (settings.status() != QSettings::NoError) throw trust::JournalError(trust::JournalCode::Uncertain);
    if (review.pendingSeedDiffers) {
        QMessageBox recovery(QMessageBox::Question, QObject::tr("Secure Sync — review unfinished first snapshot"),
            QObject::tr("An earlier first snapshot is already sealed and may have been published. "
                        "It differs from the current local copy. Review that exact snapshot for recovery? "
                        "Activation preserves the current local copy as an encrypted backup."),
            QMessageBox::Yes | QMessageBox::No, parent);
        recovery.setTextFormat(Qt::PlainText);
        recovery.setDefaultButton(QMessageBox::No);
        if (recovery.exec() != QMessageBox::Yes) return false;
        check();
    }
    QString recoveryDetails;
    if (review.pendingSeedDiffers)
        recoveryDetails += QObject::tr("\nRecovered sealed snapshot items %1\nRecovered snapshot fingerprint %2"
                                      "\nCurrent local fingerprint %3")
            .arg(qulonglong(review.pendingSeedItems)).arg(hex(review.pendingSeedDigest), hex(review.localDigest));
    if (review.retiresStaleSeed)
        recoveryDetails += QObject::tr("\nAn unfinished snapshot from an older key generation is retired locally. "
                                      "It may already have been published. Its publication evidence is retained."
                                      "\nRetirement fingerprint %1").arg(hex(review.retirementDigest));
    const auto scope = review.pendingSeedDiffers
        ? QObject::tr("Resume the exact earlier sealed snapshot in the accepted key generation. "
                      "The current local copy will be kept as an encrypted backup.")
        : review.seedsEmptyGeneration ? QObject::tr("Create the first signed snapshot in the accepted new key generation from this device's local copy. "
                      "Confirm only on the designated first device after checking cloud delivery.")
        : QObject::tr("Adopt the single verified signed version in the accepted new key generation.");
    QMessageBox consent(QMessageBox::Question, QObject::tr("Secure Sync — activate accepted key generation"),
        QObject::tr("%1\n\nGeneration %2 → %3\nLocal items %4\nNew signed version %5\nReview fingerprint %6\n\n"
                    "The old encrypted checkpoint is retained. The new checkpoint keeps a backup of the current local copy.%7")
            .arg(scope).arg(qulonglong(review.previous.generation)).arg(qulonglong(review.successor.generation))
            .arg(qulonglong(review.sourceItems)).arg(QString::fromStdString(review.successor.tipId), hex(review.confirmation)).arg(recoveryDetails),
        QMessageBox::Yes | QMessageBox::No, parent);
    consent.setTextFormat(Qt::PlainText);
    consent.setDefaultButton(QMessageBox::No);
    if (consent.exec() != QMessageBox::Yes) return false;
    check();
    destination = validatePath(destination, false);
    auto successor = *current;
    successor.checkpointDirectory = destination;
    retainSignedPredecessorMarker(successor, *current, review.sourceGeneration);
    std::async(std::launch::async, [&] {
        (void)validatePath(destination, false);
        trust::SignedJoinCheckpoint target(path(destination), credential, binding);
        trust::SignedGenerationTransition::apply(journal, identity, transport, source, target, review, review.confirmation, now(),
            [&](const trust::JoinActivation &actual) {
                successor.expected = actual;
                if (!persistSignedSuccessor(settingsFile, *current, successor, journalBinding, replicaSource))
                    throw trust::JournalError(trust::JournalCode::Uncertain);
            }, privateStaging, [&](const auto &before, const auto &after) {
                const auto currentLimit = signedTabReplicaLimit(settingsFile);
                if (currentLimit <= 0 || request.maximumItems <= 0 ||
                    after.size() > static_cast<std::size_t>(std::min(currentLimit, request.maximumItems)) ||
                    !request.preserveProtectedRows || !request.preserveProtectedRows(before, after))
                    throw trust::JournalError(trust::JournalCode::Enrollment);
            });
    }).get();
    settings.remove(Pending);
    settings.sync();
    return true;
}
}
