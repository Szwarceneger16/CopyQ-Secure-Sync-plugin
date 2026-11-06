// SPDX-License-Identifier: GPL-3.0-or-later
#include "signed_setup_wizard.h"
#include <QComboBox>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QVBoxLayout>
#include <algorithm>
#include <future>
#include <optional>

namespace cqs::native {
namespace {
using trust::SignedSetup;

struct Secret {
    crypto::Bytes bytes;
    ~Secret() { crypto::wipe(bytes); }
};
crypto::Bytes password(QLineEdit *edit) {
    auto text = edit->text();
    auto bytes = text.toUtf8();
    text.fill(QChar(0));
    edit->clear();
    crypto::Bytes result(bytes.begin(), bytes.end());
    bytes.fill(0);
    return result;
}
std::filesystem::path path(const QString &text) {
#ifdef Q_OS_WIN
    return std::filesystem::path(QDir::fromNativeSeparators(text).toStdWString());
#else
    return std::filesystem::u8path(QDir::fromNativeSeparators(text).toUtf8().toStdString());
#endif
}
trust::Token token(const QString &text) {
    const auto encoded = text.toLatin1();
    const auto bytes = QByteArray::fromHex(encoded);
    if (encoded.size() != 64 || bytes.toHex() != encoded.toLower())
        throw trust::JournalError(trust::JournalCode::Confirmation);
    trust::Token value{};
    std::copy(bytes.begin(), bytes.end(), value.begin());
    return value;
}
QString fingerprint(const trust::Genesis &genesis) {
    const auto value = SignedSetup::fingerprint(genesis);
    return QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(value.data()), value.size()).toHex());
}
void showInvitation(QWidget &parent, const trust::Genesis &genesis) {
    QDialog dialog(&parent);
    dialog.setWindowModality(Qt::ApplicationModal);
    dialog.setWindowTitle(QObject::tr("Secure Sync — public group invitation"));
    auto *layout = new QVBoxLayout(&dialog);
    auto *notice = new QLabel(QObject::tr("Give this public invitation to the new device. "
        "Compare the complete group fingerprint on a separate trusted screen before accepting its setup."), &dialog);
    notice->setTextFormat(Qt::PlainText);
    notice->setWordWrap(true);
    layout->addWidget(notice);
    auto *publicValue = new QPlainTextEdit(QString::fromStdString(SignedSetup::invitation(genesis)), &dialog);
    publicValue->setObjectName(QStringLiteral("cqsSignedSetupPublicInvitation"));
    publicValue->setReadOnly(true);
    layout->addWidget(publicValue);
    auto *digest = new QLabel(QObject::tr("Group fingerprint\n%1").arg(fingerprint(genesis)), &dialog);
    digest->setObjectName(QStringLiteral("cqsSignedSetupGroupFingerprint"));
    digest->setTextFormat(Qt::PlainText);
    digest->setTextInteractionFlags(Qt::TextSelectableByMouse);
    digest->setWordWrap(true);
    layout->addWidget(digest);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::accept);
    layout->addWidget(buttons);
    dialog.resize(640, 330);
    dialog.exec();
}
} // namespace

std::unique_ptr<SignedSetup> openSignedSetupWizard(QWidget *parent, const std::function<bool()> &stillCurrent,
    const SignedSetup::PathValidator &validatePaths) {
    QDialog dialog;
    dialog.setObjectName(QStringLiteral("cqsSignedSetup"));
    dialog.setWindowModality(Qt::ApplicationModal);
    dialog.setWindowTitle(QObject::tr("Secure Sync — signed profile setup"));
    const bool hadParent = parent != nullptr;
    const QPointer<QWidget> owner(parent);
    if (parent) QObject::connect(parent, &QObject::destroyed, &dialog, &QDialog::reject);
    auto current = [&] { return (!hadParent || owner) && (!stillCurrent || stillCurrent()); };
    auto *form = new QFormLayout(&dialog);
    auto *notice = new QLabel(QObject::tr("Create an empty signed group, prepare a new device, or unlock an existing "
        "signed profile. The password protects this device's local setup and generated keys. "
        "Choose a dedicated synchronization folder and a private local storage location outside it. "
        "Offline account recovery is not available in this setup. Keep the private profile and password."), &dialog);
    notice->setTextFormat(Qt::PlainText);
    notice->setWordWrap(true);
    form->addRow(notice);
    auto *mode = new QComboBox(&dialog);
    mode->setObjectName(QStringLiteral("cqsSignedSetupMode"));
    mode->addItems({QObject::tr("Create a new group"), QObject::tr("Join an existing group"),
                    QObject::tr("Open an existing signed profile")});
    form->addRow(QObject::tr("Action"), mode);
    auto chooser = [&](const QString &label, const QString &name) {
        auto *row = new QWidget(&dialog);
        auto *layout = new QHBoxLayout(row);
        layout->setContentsMargins(0, 0, 0, 0);
        auto *edit = new QLineEdit(row);
        edit->setReadOnly(true);
        edit->setObjectName(name);
        auto *browse = new QPushButton(QObject::tr("Choose…"), row);
        layout->addWidget(edit);
        layout->addWidget(browse);
        QObject::connect(browse, &QPushButton::clicked, &dialog, [&, edit] {
            const auto selected = QFileDialog::getExistingDirectory(&dialog, QObject::tr("Choose a dedicated folder"), {},
                QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
            if (!selected.isEmpty()) edit->setText(QDir::fromNativeSeparators(selected));
        });
        form->addRow(label, row);
        return std::make_pair(row, edit);
    };
    const auto privateFolder = chooser(QObject::tr("Private profile / new profile parent"), QStringLiteral("cqsSignedSetupPrivate"));
    const auto transport = chooser(QObject::tr("Synchronization folder"), QStringLiteral("cqsSignedSetupTransport"));
#ifdef Q_OS_WIN
    auto *volumeNotice = new QLabel(QObject::tr("For Windows publication, choose private storage on the same fixed NTFS "
        "volume as the synchronization folder."), &dialog);
    volumeNotice->setTextFormat(Qt::PlainText);
    volumeNotice->setWordWrap(true);
    form->addRow(volumeNotice);
#endif
    auto *invitation = new QPlainTextEdit(&dialog);
    invitation->setObjectName(QStringLiteral("cqsSignedSetupInvitation"));
    invitation->setMaximumHeight(90);
    form->addRow(QObject::tr("Public group invitation"), invitation);
    auto *comparison = new QLineEdit(&dialog);
    comparison->setMaxLength(64);
    comparison->setObjectName(QStringLiteral("cqsSignedSetupFingerprint"));
    form->addRow(QObject::tr("Fingerprint from the trusted device"), comparison);
    auto *secret = new QLineEdit(&dialog);
    secret->setEchoMode(QLineEdit::Password);
    secret->setObjectName(QStringLiteral("cqsSignedSetupPassword"));
    secret->setMaxLength(1024);
    form->addRow(QObject::tr("Local setup password"), secret);
    auto *repeat = new QLineEdit(&dialog);
    repeat->setObjectName(QStringLiteral("cqsSignedSetupPasswordRepeat"));
    repeat->setEchoMode(QLineEdit::Password);
    repeat->setMaxLength(1024);
    form->addRow(QObject::tr("Repeat password for a new profile"), repeat);
    auto updateMode = [&] {
        transport.first->setEnabled(mode->currentIndex() != 2);
        invitation->setEnabled(mode->currentIndex() == 1);
        comparison->setEnabled(mode->currentIndex() == 1);
        repeat->setEnabled(mode->currentIndex() != 2);
        privateFolder.second->clear();
    };
    QObject::connect(mode, &QComboBox::currentIndexChanged, &dialog, updateMode);
    updateMode();
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Open | QDialogButtonBox::Cancel, &dialog);
    QObject::connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    form->addRow(buttons);
    if (!current() || dialog.exec() != QDialog::Accepted || !current()) return {};
    const Secret credential{password(secret)};
    const Secret confirmed{password(repeat)};
    std::filesystem::path attemptedRoot;
    try {
        const int action = mode->currentIndex();
        if (action != 2 && credential.bytes != confirmed.bytes) throw crypto::Error("Passwords differ");
        if (credential.bytes.size() < 12) throw crypto::Error("Password is too short");
        const auto selectedPrivate = path(privateFolder.second->text());
        const auto selectedTransport = path(transport.second->text());
        const auto code = invitation->toPlainText().toStdString();
        const auto digest = comparison->text();
        const auto seconds = QDateTime::currentSecsSinceEpoch();
        if (seconds <= 0 || code.size() > 1024) throw trust::JournalError(trust::JournalCode::Enrollment);
        const auto genesis = action == 1 ? std::optional<trust::Genesis>(SignedSetup::parseInvitation(code)) : std::nullopt;
        const auto verifiedFingerprint = action == 1 ? token(digest) : trust::Token{};
        if (genesis && SignedSetup::fingerprint(*genesis) != verifiedFingerprint)
            throw trust::JournalError(trust::JournalCode::Confirmation);
        auto setup = std::async(std::launch::async, [&] {
            const auto now = static_cast<std::uint64_t>(seconds);
            if (action == 2) return SignedSetup::open(selectedPrivate, credential.bytes, now, validatePaths);
            attemptedRoot = SignedSetup::createPrivateRoot(selectedPrivate);
            if (action == 0) return SignedSetup::createFounder(attemptedRoot, credential.bytes, selectedTransport, now, validatePaths);
            return SignedSetup::createApplicant(attemptedRoot, credential.bytes, selectedTransport, *genesis, verifiedFingerprint, now, validatePaths);
        }).get();
        if (!current()) return {};
        QMessageBox location(QMessageBox::Information, QObject::tr("Secure Sync — signed profile"),
            QObject::tr("Keep this private profile folder and its password for the next unlock.\n%1")
                .arg(QString::fromStdString(setup->paths().root.u8string())),
            QMessageBox::Ok, &dialog);
        location.setTextFormat(Qt::PlainText);
        location.exec();
        if (!current()) return {};
        showInvitation(dialog, setup->genesis());
        if (!current()) return {};
        return setup;
    } catch (...) {
        if (current()) {
            QMessageBox refused(QMessageBox::Warning, QObject::tr("Secure Sync — signed setup refused"),
                QObject::tr("Setup could not be confirmed. Check the password, trusted invitation, empty group folder "
                            "and private folder permissions. Retain this new private profile to resume it.\n%1")
                    .arg(QString::fromStdString(attemptedRoot.u8string())), QMessageBox::Ok, &dialog);
            refused.setTextFormat(Qt::PlainText);
            refused.exec();
        }
        return {};
    }
}
} // namespace cqs::native
