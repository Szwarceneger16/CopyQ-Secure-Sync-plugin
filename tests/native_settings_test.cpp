// SPDX-License-Identifier: GPL-3.0-or-later
#include "profile.h"
#include "settings_widget.h"
#include "plugin_inventory.h"
#include "test_check.h"
#include <QApplication>
#include <QDir>
#include <QFile>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QClipboard>
#include <QJsonDocument>
#include <QTemporaryDir>
#include <iostream>

using namespace cqs::native;
int main(int argc, char **argv) {
    QApplication app(argc, argv);
    const QString active="PLUGIN securesync: enabled\n";
    CHECK(incompatiblePlugin(active+"PLUGIN itemtext: enabled\nPLUGIN itemimage: enabled\nPLUGIN itemnotes: enabled\nPLUGIN itemfakevim: enabled").isEmpty());
    CHECK(incompatiblePlugin(active+"PLUGIN itempinned: enabled\nPLUGIN itemtags: enabled").isEmpty());
    for(const auto &id:{"itemsync","itemencrypted","unknown"}) {
        CHECK(incompatiblePlugin(active+"PLUGIN "+id+": enabled")==id);
        CHECK(incompatiblePlugin(active+"PLUGIN "+id+": disabled").isEmpty());
    }
    CHECK(!incompatiblePlugin("PLUGIN itemtext: enabled").isEmpty());
    CHECK(!incompatiblePlugin(active+active).isEmpty());
    CHECK(!incompatiblePlugin(active+"PLUGIN itemtext: invalid").isEmpty());
    CHECK(!incompatiblePlugin(active+"PLUGIN broken").isEmpty());
    QTemporaryDir temp; CHECK(temp.isValid());
    const auto root = temp.path();
    CHECK(QDir().mkpath(root + "/transport/events"));
    CHECK(QDir().mkpath(root + "/private"));
    QFile key(root + "/ksync.key"); CHECK(key.open(QIODevice::WriteOnly));
    CHECK(key.write(QByteArray(32,'x')) == 32); key.close();
    Profile p{QStringLiteral("test-pc"), root+"/transport", key.fileName(), root+"/private"};
    CHECK(validateProfile(p, true).isEmpty());
    auto bad=p; bad.device="Test-pc"; CHECK(!validateProfile(bad,false).isEmpty());
    bad=p; bad.device="test-pc\n"; CHECK(!validateProfile(bad,false).isEmpty());
    bad=p; bad.keyFile=root+"/transport/ksync.key"; CHECK(!validateProfile(bad,false).isEmpty());
    bad=p; bad.stateDirectory=root+"/transport/state"; CHECK(!validateProfile(bad,false).isEmpty());
    bad=p; bad.stateDirectory=root; CHECK(!validateProfile(bad,false).isEmpty());
    bad=p; bad.transport="relative"; CHECK(!validateProfile(bad,false).isEmpty());
    bad=p; bad.transport=root+"/../transport"; CHECK(!validateProfile(bad,false).isEmpty());
    bad=p; bad.transport=root+"/transport-two"; CHECK(validateProfile(bad,false).isEmpty());
    CHECK(!validateProfile(bad,true).isEmpty()); CHECK(!QDir(bad.transport).exists());
    bad=p; bad.transport="/"; CHECK(!validateProfile(bad,false).isEmpty());
    bad=p; bad.transport="https://example.invalid/path"; CHECK(!validateProfile(bad,false).isEmpty());
    bad=p; bad.schema=9; CHECK(!validateProfile(bad,false).isEmpty());
    QSettings s(root+"/copyq.ini",QSettings::IniFormat);
    s.setValue("Options/encrypt_tabs", true);
    s.setValue("Plugins/itemsync/sentinel", "untouched");
    s.beginGroup("Plugins/securesync"); saveProfile(s,p);
    CHECK(loadProfile(s)==p); CHECK(s.allKeys().size()==8);
    auto staged=p;staged.publicationStaging=root+"/staging";CHECK(QDir().mkdir(staged.publicationStaging));
    saveProfile(s,staged);CHECK(loadProfile(s)==staged);CHECK(validateProfile(staged,true).isEmpty());saveProfile(s,p);
    bad=staged;bad.publicationStaging=root+"/transport/events";CHECK(!validateProfile(bad,false).isEmpty());
    bad=staged;bad.publicationStaging=root;CHECK(!validateProfile(bad,false).isEmpty());
    bad=staged;bad.publicationStaging="relative";CHECK(!validateProfile(bad,false).isEmpty());
    bad=staged;bad.publicationStaging=root+"/missing-stage";CHECK(!validateProfile(bad,true).isEmpty());
    s.setValue("profile_schema", 1); s.setValue("standalone_storage", true);
    CHECK(!loadProfile(s).standaloneStorage); // Legacy settings never opt in.
    auto enabled = p; enabled.standaloneStorage = true; enabled.vaultDirectory=root+"/vault"; saveProfile(s, enabled);
    CHECK(loadProfile(s) == enabled); saveProfile(s, p);
    s.setValue("profile_schema", 99); const auto unknown=loadProfile(s);
    CHECK(unknown.schema!=3); CHECK(!unknown.isEmpty());
    saveProfile(s,unknown); CHECK(s.value("profile_schema").toInt()==99);
    saveProfile(s,p); s.endGroup();
    CHECK(s.value("Options/encrypt_tabs").toBool());
    CHECK(s.value("Plugins/itemsync/sentinel").toString()=="untouched");
    s.sync(); CHECK(s.status()==QSettings::NoError);
    bool isFile=false; QString choice;
    // A migrated vault profile has a null optional import path. Editing and
    // clearing an already empty field must not change its authenticated binding.
    auto successor=p;successor.keyFile=QString{};successor.vaultDirectory=root+"/vault";
    successor.standaloneStorage=true;successor.predecessorBinding=QString(64,QChar('a'));
    SettingsWidget successorPanel(successor);
    auto *optionalKey=successorPanel.findChild<QLineEdit*>("cqsKey");CHECK(optionalKey);
    optionalKey->setText("temporary");optionalKey->clear();
    CHECK(encodeProfile(successorPanel.profile())==encodeProfile(successor));
    SettingsWidget panel(p,nullptr,[&](QWidget*,const QString&,bool file){isFile=file;return choice;});
    auto *browse=panel.findChild<QPushButton*>("cqsTransportBrowse"); CHECK(browse);
    browse->click(); CHECK(panel.profile()==p); CHECK(!isFile); // Cancel keeps value
    choice=root+"/transport-two"; browse->click(); CHECK(panel.profile().transport==choice);
    panel.setProfile(p); choice=root+"/other.key";
    panel.findChild<QPushButton*>("cqsKeyBrowse")->click(); CHECK(isFile); CHECK(panel.profile().keyFile==choice);
    panel.setProfile(unknown); CHECK(panel.profile().schema==unknown.schema);
    panel.setProfile(p);
    choice=staged.publicationStaging;panel.findChild<QPushButton*>("cqsPublicationStagingBrowse")->click();
    CHECK(!isFile&&panel.profile().publicationStaging==choice);panel.setProfile(p);
    int requested=0;
    QObject::connect(&panel,&SettingsWidget::inspectRequested,[&](Profile value){CHECK(value==p);++requested;});
    panel.findChild<QPushButton*>("cqsInspect")->click(); CHECK(requested==1);
    panel.setBusy(true); panel.findChild<QPushButton*>("cqsInspect")->click(); CHECK(requested==1);
    panel.setBusy(false);
    panel.findChild<QLineEdit*>("cqsTransport")->setText("invalid");
    panel.findChild<QPushButton*>("cqsInspect")->click(); CHECK(requested==1);
    CHECK(s.value("Plugins/securesync/transport").toString()==p.transport); // UI draft never saves itself
    CHECK(key.open(QIODevice::ReadOnly)); CHECK(key.readAll()==QByteArray(32,'x'));
    CHECK(QDir(root+"/transport/events").isEmpty());
    key.close(); CHECK(QFile::remove(key.fileName())); CHECK(QDir().mkdir(enabled.vaultDirectory));
    SettingsWidget vaultPanel(enabled);int vaultRequests=0;
    QObject::connect(&vaultPanel,&SettingsWidget::inspectRequested,[&](Profile value){CHECK(value==enabled);++vaultRequests;});
    vaultPanel.findChild<QPushButton*>("cqsInspect")->click();CHECK(vaultRequests==1);
    vaultPanel.setProfile(p);vaultPanel.findChild<QPushButton*>("cqsInspect")->click();CHECK(vaultRequests==1);
    // Status and copied diagnostics may never echo untrusted result text.
    UiContext context;context.configured=true;context.locked=false;context.verified=true;
    const QString secret="SECRET-password-key-clipboard-path-device";
    for(const auto &raw:QStringList{secret,"Waiting: "+secret,"Recovery: "+secret,"Refused: "+secret,"Unconfirmed: "+secret}){
        const auto status=presentStatus(context,raw);
        CHECK(!status.text().contains(secret)&&!status.diagnostic(context).contains(secret));
        CHECK(status.text().contains("Local data:")&&status.text().contains("Next:"));
    }
    CHECK(presentStatus(context,"Conflict: compare versions before continuing").code=="conflict");
    CHECK(presentStatus(context,"Waiting: referenced event files have not been delivered.").code=="waiting");
    context.dirty=true;CHECK(presentStatus(context,"UpToDate").saved.contains("recent edits"));
    context.saveProblem=true;CHECK(presentStatus(context,"Applied").code=="error");
    CHECK(presentStatus(context,"Applied").saved.contains("unconfirmed"));
    context.busy=true;CHECK(presentStatus(context).code=="syncing");context.busy=false;
    context.saveProblem=false;context.dirty=false;context.locked=true;CHECK(presentStatus(context).code=="locked");context.locked=false;
    context.pendingImport=true;CHECK(presentStatus(context,"Unlocked").code=="recovery");context.pendingImport=false;
    context.pendingPublication=true;CHECK(presentStatus(context,"UpToDate").code=="recovery");context.pendingPublication=false;
    context.pendingResolution=true;CHECK(presentStatus(context).code=="recovery");
    CHECK(presentStatus(context).next.contains("enable automatic synchronization"));context.pendingResolution=false;
    int operationRequests=0;
    QObject::connect(&panel,&SettingsWidget::operationRequested,[&](const QString &id){CHECK(id=="syncNow");++operationRequests;});
    auto *sync=panel.findChild<QPushButton*>("cqsOperation_syncNow");CHECK(sync);
    panel.setRuntimeStatus(context,presentStatus(context),false);sync->click();CHECK(operationRequests==0);
    panel.setRuntimeStatus(context,presentStatus(context),true);sync->click();CHECK(operationRequests==1);
    panel.setRuntimeStatus(context,presentStatus(context),true,false);sync->click();CHECK(operationRequests==1);
    CHECK(!panel.findChild<QLabel*>("cqsRuntimeStatus")->text().contains("Apply the current profile"));
    context.busy=true;panel.setRuntimeStatus(context,presentStatus(context),true);sync->click();CHECK(operationRequests==1);
    CHECK(panel.findChild<QPushButton*>("cqsOperation_stopAutomaticSync")->isEnabled());
    CHECK(!panel.findChild<QPushButton*>("cqsVaultAction_unlockStorage")->isEnabled());
    panel.findChild<QPushButton*>("cqsCopyDiagnostics")->click();
    const auto diagnostic=QApplication::clipboard()->text();CHECK(QJsonDocument::fromJson(diagnostic.toUtf8()).isObject());
    CHECK(!diagnostic.contains(root)&&!diagnostic.contains(p.device)&&!diagnostic.contains("ksync"));
    CHECK(!uiAction("syncNow');throw('injected")&&uiAction("seedHistory"));
    std::cout<<"Native profile/chooser/settings checks passed\n";
}
