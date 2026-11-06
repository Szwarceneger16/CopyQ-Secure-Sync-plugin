// SPDX-License-Identifier: GPL-3.0-or-later
#include "signed_setup_wizard.h"
#include "test_check.h"
#include <QApplication>
#include <QComboBox>
#include <QDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QTimer>
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
    bool entered = false, refused = false, invitationSeen = false;
    QString invitation;
    Driver(std::function<void(QDialog &)> action) : configure(std::move(action)) {
        QObject::connect(&timer, &QTimer::timeout, [&] {
            auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
            if (!dialog) return;
            if (dialog->objectName() == QStringLiteral("cqsSignedSetup")) {
                if (!entered) { entered = true; configure(*dialog); }
                return;
            }
            if (auto *message = qobject_cast<QMessageBox *>(dialog)) {
                if (message->windowTitle().contains(QStringLiteral("refused"))) refused = true;
                message->accept();
                return;
            }
            auto *publicValue = dialog->findChild<QPlainTextEdit *>(QStringLiteral("cqsSignedSetupPublicInvitation"));
            if (publicValue) {
                invitationSeen = true;
                invitation = publicValue->toPlainText();
                const auto *fingerprint = child<QLabel>(*dialog, "cqsSignedSetupGroupFingerprint");
                CHECK(fingerprint->text().size() >= 64);
                dialog->accept();
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
    std::cout << "Native signed setup cancel, founder, trusted fingerprint, unlock, and source boundary checks passed\n";
}
