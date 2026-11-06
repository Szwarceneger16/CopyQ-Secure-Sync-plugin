// SPDX-License-Identifier: GPL-3.0-or-later
#include "item/itemwidget.h"
#include "test_check.h"
#include "cqs-version.h"
#include <QJsonObject>
#include <QApplication>
#include <QBuffer>
#include <QDialog>
#include <QFile>
#include <QPluginLoader>
#include <QPushButton>
#include <QSettings>
#include <QStringListModel>
#include <QTemporaryDir>
#include <QTimer>
#include <QWidget>
#include <memory>
#include <iostream>

namespace {
void checkUnconfiguredSignedTab(ItemLoaderInterface &plugin) {
    const auto preamble = QByteArray::fromHex("00000001fffffffc");
    const auto descriptor = QByteArray(32, 'a') + QByteArray::fromHex("0000000000000001");
    const auto marker = preamble + QByteArrayLiteral("CQSSGN01") + descriptor;
    const auto unknownVersion = preamble + QByteArrayLiteral("CQSSGN99") + descriptor;
    for (const auto &wire : {marker, unknownVersion, preamble}) {
        QBuffer file;
        file.setData(wire);
        CHECK(file.open(QIODevice::ReadOnly));
        // The host consults recognizers before enabled status. Claiming this
        // reserved format prevents a disabled loader from allowing fallback.
        CHECK(plugin.canLoadItems(&file) && file.pos() == 0);
        QStringListModel empty;
        CHECK(!plugin.loadItems(QStringLiteral("signed_sync"), &empty, &file, 100));
        CHECK(empty.rowCount() == 0);
        CHECK(file.seek(0));
        QStringListModel occupied({QStringLiteral("keep local")});
        CHECK(!plugin.loadItems(QStringLiteral("synced_tray"), &occupied, &file, 100));
        CHECK(occupied.stringList() == QStringList{QStringLiteral("keep local")});
    }
    QStringListModel empty;
    CHECK(!plugin.canSaveItems(QStringLiteral("signed_sync")));
    CHECK(!plugin.initializeTab(QStringLiteral("signed_sync"), &empty, 100));
    CHECK(empty.rowCount() == 0);

    QBuffer ordinary;
    ordinary.setData(QByteArray::fromHex("00000000")); // CopyQ's ordinary empty tab.
    CHECK(ordinary.open(QIODevice::ReadOnly));
    CHECK(!plugin.canLoadItems(&ordinary));

    QBuffer legacy;
    legacy.setData(QByteArrayLiteral("CQSLOC01") + QByteArray(64, 'a') + descriptor.right(8));
    CHECK(legacy.open(QIODevice::ReadOnly));
    CHECK(plugin.canLoadItems(&legacy));
    CHECK(!plugin.loadItems(QStringLiteral("signed_sync"), &empty, &legacy, 100));
    CHECK(empty.rowCount() == 0);
}
} // namespace

int main(int argc,char **argv) {
    QApplication app(argc,argv); CHECK(argc==2);
    QTemporaryDir temp; CHECK(temp.isValid());
    QSettings s(temp.path()+"/profile.ini",QSettings::IniFormat);
    QPluginLoader loader(QString::fromLocal8Bit(argv[1]));
    CHECK(loader.metaData().value("MetaData").toObject().value("Version").toString()==QStringLiteral(CQS_RELEASE_VERSION));
    QObject *object=loader.instance();
    if (!object) std::cerr<<loader.errorString().toStdString()<<'\n';
    CHECK(object);
    auto *plugin=qobject_cast<ItemLoaderInterface*>(object); CHECK(plugin);
    CHECK(plugin->id()==QStringLiteral("securesync")); CHECK(plugin->supportsEncryption());
    CHECK(!plugin->canSaveItems("synced_tray")); // Does not replace Encrypt Tabs
    s.beginGroup("Plugins/securesync"); plugin->loadSettings(s);
    checkUnconfiguredSignedTab(*plugin);
    {
        std::unique_ptr<QWidget> panel(plugin->createSettingsWidget(nullptr)); CHECK(panel);
        CHECK(panel->findChild<QPushButton*>("cqsTransportBrowse"));
        CHECK(panel->findChild<QPushButton*>("cqsKeyBrowse"));
        CHECK(s.allKeys().isEmpty()); // opening UI has no persistence or sync side effects
        plugin->setEnabled(false);
        CHECK(!panel->findChild<QPushButton*>("cqsInspect")->isEnabled());
        checkUnconfiguredSignedTab(*plugin);
        plugin->setEnabled(true);
        CHECK(panel->findChild<QPushButton*>("cqsInspect")->isEnabled());
#ifdef CQS_BUILD_SIGNED_JOIN
        auto *signedJoin = panel->findChild<QPushButton *>("cqsSignedJoin");
        CHECK(signedJoin);
        const auto beforeJoin = s.allKeys(); // setEnabled(false) persists automatic_enabled.
        signedJoin->click(); // Encrypt Tabs is off in this disposable profile.
        CHECK(!QApplication::activeModalWidget());
        CHECK(s.allKeys() == beforeJoin);
        s.endGroup();
        s.setValue(QStringLiteral("Options/encrypt_tabs"), true);
        s.sync();
        s.beginGroup("Plugins/securesync");
        bool setupOpened = false;
        QTimer::singleShot(0, [&] {
            auto *setup = qobject_cast<QDialog *>(QApplication::activeModalWidget());
            CHECK(setup && setup->objectName() == QStringLiteral("cqsSignedSetup"));
            setupOpened = true;
            setup->reject();
        });
        signedJoin->click();
        CHECK(setupOpened && s.allKeys() == beforeJoin);
#else
        CHECK(!panel->findChild<QPushButton *>("cqsSignedJoin"));
#endif
        plugin->applySettings(s); CHECK(s.value("profile_schema").toInt()==3);
    }
    // Reopening after QWidget destruction exercises QPointer lifecycle safety.
    std::unique_ptr<QWidget> again(plugin->createSettingsWidget(nullptr)); CHECK(again);
    s.endGroup(); s.sync(); CHECK(s.status()==QSettings::NoError);
#ifdef CQS_BUILD_SIGNED_JOIN
    CHECK(s.value(QStringLiteral("Options/encrypt_tabs")).toBool());
    // A configured tab is still claimed when its activation is malformed.
    // A non-marker cache at its reserved path must not reach the stock loader.
    app.setApplicationName(QStringLiteral("copyq-loader-test"));
    app.setProperty("CopyQ_item_data_path", temp.filePath("items"));
    s.beginGroup("Plugins/securesync");
    s.setValue("active_signed_tab", QByteArrayLiteral("invalid activation"));
    s.sync();
    plugin->loadSettings(s);
    QStringListModel empty;
    CHECK(plugin->canSaveItems(QStringLiteral("signed_sync")));
    CHECK(!plugin->initializeTab(QStringLiteral("signed_sync"), &empty, 100));
    QFile wrongCache(temp.filePath("copyq-loader-test_tab_c2lnbmVkX3N5bmM=.dat"));
    CHECK(wrongCache.open(QIODevice::ReadWrite));
    CHECK(wrongCache.write(QByteArray::fromHex("00000000")) == 4);
    CHECK(wrongCache.seek(0) && plugin->canLoadItems(&wrongCache));
    CHECK(!plugin->loadItems(QStringLiteral("signed_sync"), &empty, &wrongCache, 100));
    CHECK(empty.rowCount() == 0);
    s.endGroup();
#endif
    std::cout<<"Native plugin loader checks passed\n";
}
