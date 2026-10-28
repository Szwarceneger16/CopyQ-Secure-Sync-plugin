// SPDX-License-Identifier: GPL-3.0-or-later
#include "item/itemwidget.h"
#include "test_check.h"
#include "cqs-version.h"
#include <QJsonObject>
#include <QApplication>
#include <QPluginLoader>
#include <QPushButton>
#include <QSettings>
#include <QTemporaryDir>
#include <QWidget>
#include <memory>
#include <iostream>

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
    {
        std::unique_ptr<QWidget> panel(plugin->createSettingsWidget(nullptr)); CHECK(panel);
        CHECK(panel->findChild<QPushButton*>("cqsTransportBrowse"));
        CHECK(panel->findChild<QPushButton*>("cqsKeyBrowse"));
        CHECK(s.allKeys().isEmpty()); // opening UI has no persistence or sync side effects
        plugin->setEnabled(false);
        CHECK(!panel->findChild<QPushButton*>("cqsInspect")->isEnabled());
        plugin->setEnabled(true);
        CHECK(panel->findChild<QPushButton*>("cqsInspect")->isEnabled());
        plugin->applySettings(s); CHECK(s.value("profile_schema").toInt()==3);
    }
    // Reopening after QWidget destruction exercises QPointer lifecycle safety.
    std::unique_ptr<QWidget> again(plugin->createSettingsWidget(nullptr)); CHECK(again);
    s.endGroup(); s.sync(); CHECK(s.status()==QSettings::NoError);
    std::cout<<"Native plugin loader checks passed\n";
}
