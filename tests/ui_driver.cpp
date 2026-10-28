// SPDX-License-Identifier: GPL-3.0-or-later
// Disposable fixture-only UI helper. Uses public Qt ABI, never QtTest/private Qt.
#include "item/itemwidget.h"
#include <QApplication>
#include <QInputDialog>
#include <QMessageBox>
#include <QAbstractButton>
#include <QAction>
#include <QFileInfo>
#include <QDir>
#include <QTimer>
#include <QFile>
#include <QListWidget>
#include <QTabWidget>
#include <QLabel>
#include <QClipboard>
#include <QVariantList>
class Probe final : public QObject, public ItemLoaderInterface {
    Q_OBJECT
    Q_PLUGIN_METADATA(IID COPYQ_PLUGIN_ITEM_LOADER_ID)
    Q_INTERFACES(ItemLoaderInterface)
public:
    Probe(){
        if(!qobject_cast<QApplication *>(QCoreApplication::instance())||qEnvironmentVariable("CQS_GUI_PUBLIC_PASSWORDS")!="1"||!qEnvironmentVariable("COPYQ_SESSION_NAME").startsWith("cqslab-"))return;
        if(QCoreApplication::applicationName()!="copyq-"+qEnvironmentVariable("COPYQ_SESSION_NAME"))return;
        auto folder=QFileInfo(qEnvironmentVariable("COPYQ_SETTINGS_PATH")).dir();
        if(!(folder.dirName().startsWith("cqs-standalone-")||(folder.cdUp()&&folder.dirName().startsWith("cqs-standalone-"))))return;
        auto *timer=new QTimer(this);timer->setInterval(100);
        connect(timer,&QTimer::timeout,this,[]{for(auto *w:QApplication::allWidgets()){
            auto *dialog=qobject_cast<QInputDialog *>(w);if(!dialog||!dialog->isVisible())continue;
            if(dialog->windowTitle()=="Secure Sync password")dialog->setTextValue("public-gui-fixture-password");
            else if(dialog->windowTitle()=="Current Tab Encryption Password"||dialog->windowTitle()=="New Tab Encryption Password"||dialog->windowTitle()=="Confirm Encryption Password")dialog->setTextValue("copyq-public-fixture-password");
            else continue;
            QTimer::singleShot(0,dialog,&QDialog::accept);
        }});
        QTimer::singleShot(300000,timer,&QObject::deleteLater);timer->start();
    }
    QString id() const override{return QStringLiteral("cqsuiprobe");}
    QString name() const override{return QStringLiteral("Disposable UI test driver");}
    QString author() const override{return {};}
    QString description() const override{return QStringLiteral("Not for installation or user profiles");}
    QVariant icon() const override{return {};}
    bool supportsEncryption() const override{return true;}
    QVariant scriptCallback(const QVariantList &a) override {
        auto folder=QFileInfo(qEnvironmentVariable("COPYQ_SETTINGS_PATH")).dir();
        const bool fixture=folder.dirName().startsWith("cqs-standalone-")||(folder.cdUp()&&folder.dirName().startsWith("cqs-standalone-"));
        if(!qEnvironmentVariable("COPYQ_SESSION_NAME").startsWith("cqslab-")||!fixture||a.isEmpty())return QStringLiteral("Refused");
        const auto command=a[0].toString();
        if(command=="ping")return QStringLiteral("Ready");
        if(command=="armEditorFixture"){
            const auto root=QFileInfo(qEnvironmentVariable("COPYQ_SETTINGS_PATH")).dir().absolutePath();
            auto *timer=new QTimer(this);timer->setInterval(100);
            connect(timer,&QTimer::timeout,this,[root,last=QByteArray{}]()mutable{
                QFile request(root+"/ui-request");if(!request.open(QIODevice::ReadOnly)||request.size()>128)return;
                const auto data=request.readAll();if(data==last)return;last=data;const auto split=data.indexOf(' ');if(split<1)return;
                const auto id=data.left(split),action=data.mid(split+1);QByteArray result="NotReady";
                if(action=="openSecureSettings"){
                    bool preferences=false;
                    for(auto *w:QApplication::allWidgets()){
                        if(w->objectName()=="cqsSettings"){result="Ready";break;}
                        if(auto *list=qobject_cast<QListWidget *>(w);list&&list->isVisible()){
                            preferences=true;
                            for(int row=0;row<list->count();++row)if(list->item(row)->text()=="Items"||list->item(row)->text()=="Secure Sync"){
                                list->setCurrentRow(row);result="Queued";break;
                            }
                        }
                    }
                    if(!preferences&&result!="Ready")for(auto *w:QApplication::topLevelWidgets())if(w->objectName()=="MainWindow")
                        for(auto *a:w->findChildren<QAction *>())if(a->shortcut()==QKeySequence("Ctrl+P")){QTimer::singleShot(0,a,&QAction::trigger);result="Queued";break;}
                }else if(action=="panelSync"||action=="panelDiagnostics"){
                    for(auto *w:QApplication::allWidgets())if(w->objectName()=="cqsSettings"){
                        if(action=="panelSync"){
                            if(auto *tabs=w->findChild<QTabWidget *>("cqsSettingsTabs"))tabs->setCurrentIndex(1);
                            if(auto *button=w->findChild<QAbstractButton *>("cqsOperation_syncNow");button&&button->isEnabled()){
                                QTimer::singleShot(0,button,&QAbstractButton::click);result="Queued";
                            }
                        }else if(auto *button=w->findChild<QAbstractButton *>("cqsCopyDiagnostics")){
                            button->click();result=QApplication::clipboard()->text().toUtf8();
                        }
                    }
                }else if(action=="closePreferences"){
                    for(auto *w:QApplication::allWidgets())if(w->isVisible()&&QString::fromLatin1(w->metaObject()->className())=="ConfigurationManager")
                        if(auto *dialog=qobject_cast<QDialog *>(w)){QTimer::singleShot(0,dialog,&QDialog::reject);result="Queued";}
                }else if(action=="activeEditors"){
                    int count=0;for(auto *w:QApplication::allWidgets())if(w->isVisible()&&QString::fromLatin1(w->metaObject()->className())=="ItemEditorWidget")++count;
                    result=QByteArray::number(count);
                }else if(action=="openEditor"){
                    for(auto *w:QApplication::topLevelWidgets())if(w->objectName()=="MainWindow"){
                        w->show();w->raise();w->activateWindow();
                        for(auto *a:w->findChildren<QAction *>())if(a->shortcut()==QKeySequence("F2")){QTimer::singleShot(0,a,&QAction::trigger);result="Queued";break;}
                    }
                }else if(action=="cancelEditor"){
                    for(auto *w:QApplication::allWidgets())if(w->isVisible()&&QString::fromLatin1(w->metaObject()->className())=="ItemEditorWidget"){
                        w->window()->show();w->window()->raise();w->window()->activateWindow();w->setFocus(Qt::OtherFocusReason);
                        if(w->hasFocus()&&QMetaObject::invokeMethod(w,"cancel",Qt::QueuedConnection))result="Queued";
                    }
                }
                for(auto *w:QApplication::allWidgets())if(auto *dialog=qobject_cast<QInputDialog *>(w);dialog&&dialog->isVisible()&&dialog->windowTitle()=="Secure Sync password"){
                    dialog->setTextValue("public-gui-fixture-password");QTimer::singleShot(0,dialog,&QDialog::accept);
                }
                QFile response(root+"/ui-response");if(response.open(QIODevice::WriteOnly|QIODevice::Truncate))response.write(id+' '+result);
            });
            QTimer::singleShot(180000,timer,&QObject::deleteLater);timer->start();return QStringLiteral("Queued");
        }
        if(command=="activeEditors"){
            int count=0;for(auto *w:QApplication::allWidgets())if(w->isVisible()&&QString::fromLatin1(w->metaObject()->className())=="ItemEditorWidget")++count;
            return count;
        }
        if(command=="armConflictDecision"&&a.size()==2&&a[1].toString()=="Keep both versions"){
            auto *timer=new QTimer(this);timer->setInterval(100);
            connect(timer,&QTimer::timeout,this,[timer]{for(auto *w:QApplication::allWidgets()){
                if(auto *dialog=qobject_cast<QInputDialog *>(w);dialog&&dialog->isVisible()&&dialog->windowTitle()=="Secure Sync — conflict"){
                    dialog->setTextValue("Keep both versions");QTimer::singleShot(0,dialog,&QDialog::accept);
                }
                if(auto *dialog=qobject_cast<QMessageBox *>(w);dialog&&dialog->isVisible()&&dialog->windowTitle()=="Secure Sync — confirm resolution"){
                    auto *yes=dialog->button(QMessageBox::Yes);if(yes)QTimer::singleShot(0,yes,&QAbstractButton::click);
                }
            }});
            QTimer::singleShot(120000,timer,&QObject::deleteLater);timer->start();return QStringLiteral("Queued");
        }
        if(command=="armPublicPasswords"&&a.size()==3&&a[1].toString()=="public-fixture-password"&&a[2].toString()=="copyq-public-fixture-password"){
            // Passive fixture input continues after this helper's saver is
            // disabled, so production inventory checks remain unchanged.
            auto *timer=new QTimer(this);timer->setInterval(100);
            connect(timer,&QTimer::timeout,this,[]{for(auto *w:QApplication::allWidgets()){
                auto *dialog=qobject_cast<QInputDialog *>(w);if(!dialog||!dialog->isVisible())continue;
                if(dialog->windowTitle()=="Secure Sync password")dialog->setTextValue("public-fixture-password");
                else if(dialog->windowTitle()=="Current Tab Encryption Password")dialog->setTextValue("copyq-public-fixture-password");
                else continue;
                QTimer::singleShot(0,dialog,&QDialog::accept);
            }});
            QTimer::singleShot(60000,timer,&QObject::deleteLater);timer->start();return QStringLiteral("Queued");
        }
        if(command=="disable"){setEnabled(false);return QStringLiteral("Disabled");}
        for(auto *w:QApplication::allWidgets()){
            if(!w->isVisible())continue;
            if(command=="input"&&a.size()==3){auto *dialog=qobject_cast<QInputDialog *>(w);
                if(dialog&&dialog->windowTitle()==a[1].toString()){
                    dialog->setTextValue(a[2].toString());QTimer::singleShot(0,dialog,&QDialog::accept);return QStringLiteral("Queued");}}
            if(command=="message"&&a.size()==2){auto *dialog=qobject_cast<QMessageBox *>(w);
                if(dialog&&dialog->windowTitle()==a[1].toString()){
                    QTimer::singleShot(0,dialog,&QDialog::accept);return QStringLiteral("Queued");}}
            if(command=="click"&&a.size()==2&&w->objectName()==a[1].toString()){
                if(auto *button=qobject_cast<QAbstractButton *>(w)){QTimer::singleShot(0,button,&QAbstractButton::click);return QStringLiteral("Queued");}}
            if(command=="cancelEditor"&&QString::fromLatin1(w->metaObject()->className())=="ItemEditorWidget") {
                w->window()->show();w->window()->raise();w->window()->activateWindow();w->setFocus(Qt::OtherFocusReason);
                if(!w->hasFocus())return QStringLiteral("NotReady");
                return QMetaObject::invokeMethod(w,"cancel",Qt::QueuedConnection)?QStringLiteral("Queued"):QStringLiteral("NotReady");
            }
            if(command=="closePreferences"&&QString::fromLatin1(w->metaObject()->className())=="ConfigurationManager"){
                if(auto *dialog=qobject_cast<QDialog *>(w)){QTimer::singleShot(0,dialog,&QDialog::reject);return QStringLiteral("Queued");}}
        }
        if(command=="shortcut"&&a.size()==2){
            for(auto *w:QApplication::topLevelWidgets())if(w->objectName()=="MainWindow"){
                w->show();w->raise();w->activateWindow();
                for(auto *action:w->findChildren<QAction *>())if(action->shortcut()==QKeySequence(a[1].toString())){
                    QTimer::singleShot(0,action,&QAction::trigger);return QStringLiteral("Queued");}
            }
        }
        return QStringLiteral("NotReady");
    }
};
#include "ui_driver.moc"
