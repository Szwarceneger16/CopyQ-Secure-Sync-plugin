// SPDX-License-Identifier: GPL-3.0-or-later
#include "signed_setup_wizard.h"
#include "signed_join_entry.h"
#include "signed_join_checkpoint.h"
#include "signed_tab_activation.h"
#include "storage.h"
#include "packed_items.h"
#include "test_check.h"
#include <QAbstractButton>
#include <QApplication>
#include <QComboBox>
#include <QDateTime>
#include <QDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSettings>
#include <QTimer>
#include <algorithm>
#include <filesystem>
#include <iostream>
#ifdef _WIN32
#include "windows_test_acl.h"
#endif

namespace {
using namespace cqs;
using namespace cqs::trust;
using cqs::native::openSignedSetupWizard;
constexpr auto Password = "synthetic-native-setup-password";

QString path(const std::filesystem::path &value) {
    return QString::fromStdString(value.u8string());
}
struct Temporary {
    std::filesystem::path root = SignedSetup::createPrivateRoot(std::filesystem::temp_directory_path());
    ~Temporary() { std::error_code ignored; std::filesystem::remove_all(root, ignored); }
    std::filesystem::path directory(const std::string &name) const {
        const auto result = root / name;
#ifdef _WIN32
        cqs::testing::directory(result);
#else
        CHECK(std::filesystem::create_directory(result));
        std::filesystem::permissions(result, std::filesystem::perms::owner_all);
#endif
        return result;
    }
};
template<class T> T *child(QDialog &dialog, const char *name) {
    auto *value = dialog.findChild<T *>(QString::fromLatin1(name));
    CHECK(value);
    return value;
}
std::size_t entries(const std::filesystem::path &directory) {
    return std::distance(std::filesystem::directory_iterator(directory), std::filesystem::directory_iterator());
}

// Drive the real modal workflow; cryptographic work runs without processing UI
// events, so a timer only acknowledges the dialogs after completion.
struct Driver {
    QTimer timer;
    std::function<void(QDialog &)> configure;
    std::function<void(QDialog &)> operate;
    bool entered = false, refused = false, invitationSeen = false, operated = false;
    QString invitation;
    Driver(std::function<void(QDialog &)> action, std::function<void(QDialog &)> operation = {})
        : configure(std::move(action)), operate(std::move(operation)) {
        QObject::connect(&timer, &QTimer::timeout, [&] {
            auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
            if (!dialog) return;
            if (dialog->objectName() == QStringLiteral("cqsSignedSetup")) {
                if (!entered) { entered = true; configure(*dialog); }
                return;
            }
            if (auto *message = qobject_cast<QMessageBox *>(dialog)) {
                if (message->windowTitle().contains(QStringLiteral("refused"))) refused = true;
                if (auto *yes = message->button(QMessageBox::Yes)) yes->click();
                else message->accept();
                return;
            }
            auto *publicValue = dialog->findChild<QPlainTextEdit *>(QStringLiteral("cqsSignedSetupPublicInvitation"));
            if (publicValue) {
                invitationSeen = true;
                invitation = publicValue->toPlainText();
                const auto *fingerprint = child<QLabel>(*dialog, "cqsSignedSetupGroupFingerprint");
                CHECK(fingerprint->text().size() >= 64);
                dialog->accept();
                return;
            }
            if (operate && !operated) {
                operated = true;
                QTimer::singleShot(0, dialog, [this, dialog] { operate(*dialog); });
            }
        });
        timer.start(1);
    }
};
void fill(QDialog &dialog, int mode, const std::filesystem::path &privateDirectory,
          const std::filesystem::path &transport = {}) {
    child<QComboBox>(dialog, "cqsSignedSetupMode")->setCurrentIndex(mode);
    child<QLineEdit>(dialog, "cqsSignedSetupPrivate")->setText(path(privateDirectory));
    child<QLineEdit>(dialog, "cqsSignedSetupTransport")->setText(path(transport));
    child<QLineEdit>(dialog, "cqsSignedSetupPassword")->setText(QString::fromLatin1(Password));
    if (mode != 2)
        child<QLineEdit>(dialog, "cqsSignedSetupPasswordRepeat")->setText(QString::fromLatin1(Password));
}

void exerciseGuidedPublication(Temporary &temporary) {
    using namespace cqs::native;
    const auto now = [] { return std::uint64_t(QDateTime::currentSecsSinceEpoch()); };
    const auto shared = temporary.directory("entry-shared");
    const auto root = SignedSetup::createPrivateRoot(temporary.root);
    const std::string passwordText(Password);
    const crypto::Bytes password(passwordText.begin(), passwordText.end());
    auto setup = SignedSetup::createFounder(root, password, shared, now());
    const auto settingsFile = path(temporary.root / "entry-profile.ini");
    QSettings settings(settingsFile, QSettings::IniFormat);
    settings.setValue("Options/encrypt_tabs", true);
    settings.sync();
    CHECK(settings.status() == QSettings::NoError);
    const auto journalBinding = TrustJournal::binding(setup->genesis(), setup->member());
    const auto binding = signedTabBinding(settingsFile, path(setup->paths().checkpoint), journalBinding);
    const auto journalKey = setup->journalCredential();
    const auto checkpointKey = setup->checkpointCredential();
    JoinActivation activation;
    {
        state::FileStore store(setup->paths().journal, journalBinding, journalKey);
        TrustJournal journal(store, setup->genesis(), setup->member(), setup->founderKey());
        const storage::Directory transport(shared);
        activation = journal.preflightJoinActivation(setup->identity(), transport, binding, now());
        SignedJoinCheckpoint checkpoint(setup->paths().checkpoint, checkpointKey, binding);
        journal.applyJoinActivation(setup->identity(), transport, activation, now(), [&](const auto &verified, const auto &tip, const auto &snapshot) {
            checkpoint.apply(verified, tip, snapshot);
        });
    }
    const auto snapshot = [](const std::string &value) {
        return transaction::Snapshot{{{"text/plain", crypto::Bytes(value.begin(), value.end())}}};
    };
    const auto edit = [&](const auto &value) {
        SignedJoinCheckpoint checkpoint(setup->paths().checkpoint, checkpointKey, binding);
        const auto mounted = checkpoint.mount(activation);
        mounted->save(value, mounted->generation());
    };
    const auto verify = [&](std::size_t count, const auto &value) {
        state::FileStore store(setup->paths().journal, journalBinding, journalKey);
        TrustJournal journal(store, setup->genesis(), setup->member(), setup->founderKey());
        const auto history = journal.scanClipboardEvents(*setup->founderKey(), storage::Directory(shared), now());
        CHECK(history.events.size() == count && history.graph.tips().size() == 1);
        const auto tip = history.graph.tips().front();
        const auto found = std::find_if(history.events.begin(), history.events.end(), [&](const auto &event) {
            return event.revision.id == tip;
        });
        CHECK(found != history.events.end() && packed::decode(found->items) == value);
        SignedJoinCheckpoint checkpoint(setup->paths().checkpoint, checkpointKey, binding);
        CHECK(checkpoint.mount(activation)->snapshot() == value);
    };
    SignedReplicaTask retainedTask;
    const auto request = [&] {
        return SignedReplicaRequest{activation, 100, true, [] { return true; }, [](const auto &, const auto &) { return true; }};
    };
    const auto open = [&](const QString &action) {
        Driver driver([&](QDialog &dialog) { fill(dialog, 2, root); dialog.accept(); }, [&](QDialog &dialog) {
            const auto buttons = dialog.findChildren<QPushButton *>();
            const auto selected = std::find_if(buttons.begin(), buttons.end(), [&](const auto *button) {
                return button->text() == action;
            });
            CHECK(selected != buttons.end());
            (*selected)->click();
            dialog.reject();
        });
        openGuidedSignedJoinSetup(nullptr, settingsFile, {}, [] { return true; }, {},
            [&](const auto &directory, const auto &key, const auto &actualBinding, const auto &source) {
                CHECK(directory == path(setup->paths().checkpoint) && key.isEmpty() && actualBinding == journalBinding);
                CHECK(source.transport == path(shared) && source.journal == path(setup->paths().journal) && source.setupRoot == path(root));
                return std::optional<SignedReplicaRequest>(request());
            }, [&](const auto &, const auto &, const auto &, const auto &, SignedReplicaTask task) {
                CHECK(!retainedTask);
                retainedTask = std::move(task);
                return true;
            });
        CHECK(driver.entered && driver.invitationSeen && driver.operated && !driver.refused);
    };
    const auto manual = snapshot("synthetic guided manual publication");
    edit(manual);
    open(QStringLiteral("Synchronize signed_sync"));
    verify(2, manual);
    open(QStringLiteral("Start signed background synchronization"));
    CHECK(retainedTask);
    const auto background = snapshot("synthetic guided background publication");
    edit(background);
    CHECK(retainedTask(request(), [] { return true; }) == SignedReplicaResult::Published);
    verify(3, background);
}
} // namespace

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    Temporary temporary;
    const auto shared = temporary.directory("shared");
    const auto before = entries(temporary.root);
    {
        Driver driver([](QDialog &dialog) { dialog.reject(); });
        CHECK(!openSignedSetupWizard(nullptr));
        CHECK(driver.entered && !driver.invitationSeen && !driver.refused);
    }
    CHECK(entries(temporary.root) == before && std::filesystem::is_empty(shared));

    std::unique_ptr<SignedSetup> founder;
    {
        Driver driver([&](QDialog &dialog) { fill(dialog, 0, temporary.root, shared); dialog.accept(); });
        founder = openSignedSetupWizard(nullptr);
        CHECK(founder && driver.entered && driver.invitationSeen && !driver.refused);
        CHECK(driver.invitation.toStdString() == SignedSetup::invitation(founder->genesis()));
    }
    const auto initialCount = entries(temporary.root);
    const auto genesis = founder->genesis();
    {
        Driver driver([&](QDialog &dialog) {
            fill(dialog, 1, temporary.root, shared);
            child<QPlainTextEdit>(dialog, "cqsSignedSetupInvitation")->setPlainText(
                QString::fromStdString(SignedSetup::invitation(genesis)));
            child<QLineEdit>(dialog, "cqsSignedSetupFingerprint")->setText(QString(64, QChar('0')));
            dialog.accept();
        });
        CHECK(!openSignedSetupWizard(nullptr));
        CHECK(driver.refused && !driver.invitationSeen);
    }
    CHECK(entries(temporary.root) == initialCount);
    {
        Driver driver([&](QDialog &dialog) { fill(dialog, 2, founder->paths().root); dialog.accept(); });
        auto reopened = openSignedSetupWizard(nullptr);
        CHECK(reopened && reopened->member() == founder->member());
        CHECK(reopened->checkpointCredential() == founder->checkpointCredential());
        CHECK(driver.invitationSeen && !driver.refused);
    }
    // A rejected source boundary cannot initialize a manifest or publish history.
    const auto rejectedShared = temporary.directory("rejected-shared");
    std::filesystem::path attempted;
    {
        Driver driver([&](QDialog &dialog) { fill(dialog, 0, temporary.root, rejectedShared); dialog.accept(); });
        CHECK(!openSignedSetupWizard(nullptr, {}, [&](const auto &root, const auto &transport) {
            attempted = root;
            CHECK(transport == rejectedShared);
            return false;
        }));
        CHECK(driver.refused && !driver.invitationSeen);
    }
    CHECK(!attempted.empty() && std::filesystem::is_empty(attempted));
    CHECK(std::filesystem::is_empty(rejectedShared));
    exerciseGuidedPublication(temporary);
    std::cout << "Native signed setup cancel, founder, trusted fingerprint, unlock, and source boundary checks passed\n";
}
