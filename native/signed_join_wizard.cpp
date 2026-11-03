// SPDX-License-Identifier: GPL-3.0-or-later
#include "signed_join_wizard.h"
#include "device_identity.h"
#include "device_join_dialog.h"
#include "device_trust_journal.h"
#include "signed_join_checkpoint.h"
#include "storage.h"

#include <QByteArray>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QEventLoop>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QStringList>
#include <QThread>
#include <QVBoxLayout>

#include <algorithm>
#include <exception>
#include <memory>
#include <optional>
#include <utility>

namespace cqs::native {
namespace {
using namespace cqs::trust;
using crypto::Bytes;

constexpr auto RequestPrefix = "cqs-join-request-v1/";
constexpr qsizetype TokenHexSize = 64;
constexpr qsizetype RequestBytes = 128;
constexpr qsizetype PacketHexLimit = 2 * storage::MaxControlPacketBytes;

[[noreturn]] void invalidInput() { throw Error(ErrorCode::Invalid); }

std::uint64_t now() {
    const auto seconds = QDateTime::currentSecsSinceEpoch();
    if (seconds <= 0) throw JournalError(JournalCode::ClockRollback);
    return static_cast<std::uint64_t>(seconds);
}

template<class Container>
QString hex(const Container &bytes) {
    return QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(bytes.data()),
                                          static_cast<qsizetype>(bytes.size())).toHex());
}

Bytes parseHex(const QString &input, qsizetype maximum) {
    if (input.isEmpty() || input.size() > maximum || input.size() % 2 != 0) invalidInput();
    for (const auto ch : input) {
        const auto c = ch.unicode();
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            invalidInput();
    }
    const auto bytes = QByteArray::fromHex(input.toLatin1());
    return {bytes.begin(), bytes.end()};
}

Token tokenAt(const Bytes &bytes, std::size_t offset) {
    Token token{};
    if (offset > bytes.size() || bytes.size() - offset < token.size()) invalidInput();
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset), token.size(), token.begin());
    return token;
}

Token parseToken(const QString &value) {
    if (value.size() != TokenHexSize) invalidInput();
    return tokenAt(parseHex(value, TokenHexSize), 0);
}

QString encodeRequest(const JoinRequest &request) {
    return QLatin1String(RequestPrefix) + hex(request.applicant.id) + hex(request.applicant.signingKey)
           + hex(request.applicant.encryptionKey) + hex(request.request);
}

JoinRequest decodeRequest(const QString &wire) {
    const auto prefix = QLatin1String(RequestPrefix);
    if (wire.size() != prefix.size() + 2 * RequestBytes || !wire.startsWith(prefix)) invalidInput();
    const auto bytes = parseHex(wire.mid(prefix.size()), 2 * RequestBytes);
    return {{tokenAt(bytes, 0), tokenAt(bytes, 32), tokenAt(bytes, 64)}, tokenAt(bytes, 96)};
}

// Check aggregate size before copying or splitting, then bound the number and
// size of every individual public input. Clipboard contents are never read.
QStringList boundedLines(const QString &input, qsizetype lineLimit) {
    const auto countLimit = static_cast<qsizetype>(MaxMembers);
    if (input.size() > countLimit * (lineLimit + 2)) invalidInput();
    auto lines = input.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    if (lines.isEmpty() || lines.size() > countLimit) invalidInput();
    for (auto &line : lines) {
        if (line.endsWith(QLatin1Char('\r'))) line.chop(1);
        if (line.isEmpty() || line.size() > lineLimit) invalidInput();
    }
    return lines;
}

std::vector<Token> approverIds(const QString &input) {
    std::vector<Token> result;
    for (const auto &line : boundedLines(input, TokenHexSize)) result.push_back(parseToken(line));
    return result;
}

Certificate combinedCertificate(const QString &input) {
    std::optional<Certificate> result;
    Bytes proposal;
    for (const auto &line : boundedLines(input, PacketHexLimit)) {
        const auto part = decodeCertificate(parseHex(line, PacketHexLimit));
        const auto encoded = encodeProposal(part.proposal);
        if (!result) {
            result = Certificate{part.proposal, {}};
            proposal = encoded;
        }
        if (proposal != encoded || part.approvals.size() > MaxMembers - result->approvals.size()) invalidInput();
        result->approvals.insert(result->approvals.end(), part.approvals.begin(), part.approvals.end());
    }
    // Round-tripping sorts approvals and rejects repeated signers before a
    // review can display or accept the assembled certificate.
    return decodeCertificate(encodeCertificate(*result));
}

template<class Action>
auto onWorker(Action action) {
    std::optional<decltype(action())> result;
    std::exception_ptr failure;
    QEventLoop loop;
    const std::unique_ptr<QThread> worker(QThread::create([&] {
        try { result.emplace(action()); }
        catch (...) { failure = std::current_exception(); }
    }));
    QObject::connect(worker.get(), &QThread::finished, &loop, &QEventLoop::quit, Qt::QueuedConnection);
    worker->start();
    loop.exec(QEventLoop::ExcludeUserInputEvents);
    worker->wait();
    if (failure) std::rethrow_exception(failure);
    return std::move(result).value();
}

std::optional<QString> input(QWidget &parent, const QString &label, bool multiline = false) {
    bool accepted = false;
    const auto title = QObject::tr("Secure Sync — signed device Join");
    const auto value = multiline
        ? QInputDialog::getMultiLineText(&parent, title, label, {}, &accepted)
        : QInputDialog::getText(&parent, title, label, QLineEdit::Normal, {}, &accepted);
    if (!accepted) return std::nullopt;
    return value;
}

void showPublicValue(QWidget &parent, const QString &label, const QString &value) {
    QDialog dialog(&parent);
    dialog.setWindowTitle(QObject::tr("Secure Sync — public Join message"));
    auto *layout = new QVBoxLayout(&dialog);
    auto *description = new QLabel(label, &dialog);
    description->setWordWrap(true);
    layout->addWidget(description);
    auto *wire = new QPlainTextEdit(value, &dialog);
    wire->setReadOnly(true);
    layout->addWidget(wire);
    auto *close = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    QObject::connect(close, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(close);
    dialog.resize(660, 300);
    dialog.exec();
}

template<class Action>
void addAction(QDialog &dialog, QVBoxLayout &layout, const QString &name, Action action) {
    auto *button = new QPushButton(name, &dialog);
    layout.addWidget(button);
    QObject::connect(button, &QPushButton::clicked, &dialog, [&, action = std::move(action)] {
        try { action(); }
        catch (...) {
            // Do not surface exception details, private paths, keys or payloads
            // through this UI. The backend defines exact retry semantics.
            if (dialog.isVisible())
                QMessageBox::warning(&dialog, QObject::tr("Secure Sync — Join refused"),
                    QObject::tr("The operation failed or its durable outcome is unconfirmed. "
                                "Check the current membership, packet and local permissions. "
                                "Reopen the wizard before retrying the same operation."));
        }
    });
}
} // namespace

void runSignedJoinWizard(QWidget *parent, TrustJournal &journal, const Identity &identity,
                         const storage::Directory &transport, SignedJoinCheckpoint &checkpoint,
                         const std::string &profileBinding, const SyncKey *publishKey,
                         const std::filesystem::path &privateStaging, const std::function<bool()> &stillCurrent) {
    // The preferences widget can be deleted by the host while a modal dialog
    // runs. The wizard is stack-owned so that its worker can always be joined.
    QDialog wizard;
    wizard.setWindowModality(Qt::ApplicationModal);
    const bool hasParent = parent != nullptr;
    const QPointer<QWidget> originalParent(parent);
    if (parent) QObject::connect(parent, &QObject::destroyed, &wizard, &QDialog::reject);
    const auto checkCurrent = [&] {
        if ((hasParent && !originalParent) || (stillCurrent && !stillCurrent()))
            throw JournalError(JournalCode::Enrollment);
    };
    wizard.setWindowTitle(QObject::tr("Secure Sync — signed device Join"));
    const auto run = [&](auto action) {
        checkCurrent();
        auto result = onWorker(std::move(action));
        checkCurrent();
        return result;
    };
    auto *layout = new QVBoxLayout(&wizard);
    auto *notice = new QLabel(QObject::tr(
        "Exchange only the public Join messages. Compare the full values on independent trusted "
        "screens. A storage receipt confirms that the sealed group key was saved. A signed checkpoint confirms "
        "an encrypted local copy of the reviewed history."), &wizard);
    notice->setWordWrap(true);
    layout->addWidget(notice);
    auto *local = new QLabel(QObject::tr("Local device ID %1").arg(hex(identity.member().id)), &wizard);
    local->setTextFormat(Qt::PlainText);
    local->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(local);
    addAction(wizard, *layout, QObject::tr("Inspect signed membership"), [&] {
        const auto status = run([&] { return journal.inspect(); });
        const auto &state = status.state;
        const bool active = std::find(state.members.begin(), state.members.end(), identity.member()) != state.members.end();
        const auto membership = status.forked ? QObject::tr("Conflict detected") :
                                (active ? QObject::tr("Active member") : QObject::tr("No current membership"));
        QMessageBox::information(&wizard, QObject::tr("Secure Sync — signed membership"),
            QObject::tr("%1\nGroup %2\nGeneration %3\nVerified Join %4\nSealed key stored %5")
                .arg(membership, hex(state.group), QString::number(static_cast<qulonglong>(state.keyGeneration)),
                     status.verifiedJoin ? QObject::tr("Yes") : QObject::tr("No"),
                     status.installedKey ? QObject::tr("Yes") : QObject::tr("No")));
    });
    auto *columns = new QHBoxLayout;
    layout->addLayout(columns);
    auto *applicant = new QGroupBox(QObject::tr("Device requesting access"), &wizard);
    auto *member = new QGroupBox(QObject::tr("Existing device"), &wizard);
    auto *applicantActions = new QVBoxLayout(applicant);
    auto *memberActions = new QVBoxLayout(member);
    columns->addWidget(applicant);
    columns->addWidget(member);

    addAction(wizard, *applicantActions, QObject::tr("1. Create or reopen request"), [&] {
        const auto request = run([&] { return journal.beginJoin(identity, now()); });
        showPublicValue(wizard, QObject::tr("Send this public request to an existing device."), encodeRequest(request));
    });
    addAction(wizard, *memberActions, QObject::tr("1. Prepare Add proposal"), [&] {
        const auto value = input(wizard, QObject::tr("Paste the public request from the requesting device."));
        if (!value) return;
        const auto request = decodeRequest(*value);
        const auto proposal = run([&] {
            const auto time = now();
            return journal.proposeJoin(request, time, time + 15 * 60);
        });
        showPublicValue(wizard, QObject::tr("Send this public Add proposal to the applicant and each intended approver."),
                        hex(encodeProposal(proposal)));
    });
    addAction(wizard, *applicantActions, QObject::tr("2. Show comparison before approvals"), [&] {
        const auto value = input(wizard, QObject::tr("Paste the public Add proposal."));
        if (!value) return;
        const auto proposal = decodeProposal(parseHex(*value, PacketHexLimit));
        const auto ids = input(wizard, QObject::tr("Enter the intended approvers' full device IDs, one per line."), true);
        if (!ids) return;
        const auto signers = approverIds(*ids);
        const auto review = run([&] { return journal.reviewJoin(proposal, signers, now()); });
        showDeviceJoinReview(&wizard, review);
    });
    addAction(wizard, *memberActions, QObject::tr("2. Compare and sign approval"), [&] {
        const auto value = input(wizard, QObject::tr("Paste the public Add proposal."));
        if (!value) return;
        const auto proposal = decodeProposal(parseHex(*value, PacketHexLimit));
        const auto review = run([&] { return journal.reviewJoinApproval(proposal, now()); });
        const auto confirmed = confirmDeviceJoinReview(&wizard, review);
        if (!confirmed) return;
        if (confirmed->size() != 1 || confirmed->front().approver != identity.member().id) invalidInput();
        const auto approval = run([&] { return journal.approve(proposal, identity, confirmed->front().digest, now()); });
        showPublicValue(wizard, QObject::tr("Send this public signed approval to the applicant."),
                        hex(encodeCertificate({proposal, {approval}})));
    });
    addAction(wizard, *applicantActions, QObject::tr("3. Verify signed approvals"), [&] {
        const auto value = input(wizard, QObject::tr("Paste the public signed approval packets, one per line."), true);
        if (!value) return;
        const auto certificate = combinedCertificate(*value);
        if (certificate.proposal.operation != Operation::Add || certificate.proposal.subject != identity.member())
            invalidInput();
        const auto resumed = run([&] { return journal.inspect().verifiedJoin; });
        std::vector<JoinConfirmation> confirmations;
        if (!resumed) {
            std::vector<Token> signers;
            for (const auto &approval : certificate.approvals) signers.push_back(approval.signer);
            const auto review = run([&] { return journal.reviewJoin(certificate.proposal, signers, now()); });
            const auto confirmed = confirmDeviceJoinReview(&wizard, review);
            if (!confirmed) return;
            confirmations = *confirmed;
        }
        (void)run([&] { return journal.acceptJoin(certificate, confirmations, now()); });
        showPublicValue(wizard, QObject::tr("Send the verified public membership certificate to the existing devices."),
                        hex(encodeCertificate(certificate)));
    });
    addAction(wizard, *memberActions, QObject::tr("3. Record membership certificate"), [&] {
        const auto value = input(wizard, QObject::tr("Paste the public membership certificate."));
        if (!value) return;
        const auto certificate = decodeCertificate(parseHex(*value, PacketHexLimit));
        const auto outcome = run([&] {
            // A first admission of this device always requires independent
            // comparisons. Once admitted, observing a conflicting Add can
            // still persist fork evidence and stop subsequent operations.
            if (certificate.proposal.operation == Operation::Add &&
                certificate.proposal.subject.id == identity.member().id &&
                !journal.inspect().verifiedJoin) invalidInput();
            return journal.observe(certificate, now());
        });
        if (outcome == ObserveResult::ForkDetected) {
            QMessageBox::warning(&wizard, QObject::tr("Secure Sync — membership conflict"),
                QObject::tr("A conflicting membership certificate was recorded. Signed Join is blocked."));
        } else {
            QMessageBox::information(&wizard, QObject::tr("Secure Sync"), QObject::tr("Membership certificate verified."));
        }
    });
    addAction(wizard, *memberActions, QObject::tr("4. Publish sealed key for a member"), [&] {
        const auto value = input(wizard, QObject::tr("Enter the intended recipient's full device ID."));
        if (!value) return;
        const auto recipient = parseToken(*value);
        if (QMessageBox::question(&wizard, QObject::tr("Secure Sync — confirm key delivery"),
            QObject::tr("Publish the current group key, sealed for this member?\n\n%1").arg(hex(recipient)),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) return;
        const auto address = run([&] {
            transport.checkPublicationStaging(privateStaging);
            const auto installed = publishKey ? std::unique_ptr<SyncKey>{} : journal.loadInstalledKey(identity, now());
            const auto &key = publishKey ? *publishKey : *installed;
            (void)journal.prepareDelivery(recipient, identity, key, now());
            return journal.publishDelivery(recipient, transport, now(), privateStaging);
        });
        showPublicValue(wizard, QObject::tr("Send this immutable sealed key packet address to the recipient."),
                        QString::fromStdString(address));
    });
    addAction(wizard, *applicantActions, QObject::tr("4. Install sealed key"), [&] {
        const auto value = input(wizard, QObject::tr("Enter the immutable sealed key packet address."));
        if (!value) return;
        const auto address = hex(parseToken(*value)).toStdString();
        const auto receipt = run([&] {
            if (!journal.inspect().verifiedJoin) throw JournalError(JournalCode::Enrollment);
            return journal.installDelivery(transport.readControl(address), identity, now());
        });
        showPublicValue(wizard, QObject::tr("The sealed key is stored. Send this public storage receipt to the sender."),
                        hex(receipt));
    });
    addAction(wizard, *memberActions, QObject::tr("Record a storage receipt"), [&] {
        const auto value = input(wizard, QObject::tr("Paste the public storage receipt from the recipient."));
        if (!value) return;
        const auto receipt = parseHex(*value, PacketHexLimit);
        (void)run([&] { return journal.recordReceipt(receipt, now()); });
        QMessageBox::information(&wizard, QObject::tr("Secure Sync"), QObject::tr("Storage receipt verified."));
    });
    addAction(wizard, *applicantActions, QObject::tr("5. Review and write signed checkpoint"), [&] {
        const auto expected = run([&] {
            return journal.preflightJoinActivation(identity, transport, profileBinding, now());
        });
        if (QMessageBox::question(&wizard, QObject::tr("Secure Sync — confirm checkpoint"),
            QObject::tr("Write this verified history as an encrypted private checkpoint?\n\n"
                        "Group %1\nGeneration %2\nTip %3\nPacket digest %4\nProfile binding %5")
                .arg(hex(expected.group), QString::number(static_cast<qulonglong>(expected.generation)),
                     QString::fromStdString(expected.tipId), hex(expected.tipDigest),
                     QString::fromStdString(expected.profileBinding)),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) return;
        (void)run([&] {
            journal.applyJoinActivation(identity, transport, expected, now(),
                [&](const JoinActivation &verified, const events::Event &tip, const transaction::Snapshot &snapshot) {
                    checkpoint.apply(verified, tip, snapshot);
                });
            return true;
        });
        QMessageBox::information(&wizard, QObject::tr("Secure Sync"), QObject::tr("Encrypted signed checkpoint verified."));
    });
    applicantActions->addStretch();
    memberActions->addStretch();
    auto *close = new QDialogButtonBox(QDialogButtonBox::Close, &wizard);
    QObject::connect(close, &QDialogButtonBox::rejected, &wizard, &QDialog::reject);
    layout->addWidget(close);
    wizard.resize(690, 340);
    wizard.exec();
}
} // namespace cqs::native
