// SPDX-License-Identifier: GPL-3.0-or-later
#include "transport_watch.h"
#include <QDir>
#include <QDirIterator>
#include <QFileInfo>
#include <QSet>

namespace cqs::native {
TransportWatch::TransportWatch(QObject *parent):QObject(parent) {
    refresh_.setSingleShot(true);refresh_.setInterval(250);
    connect(&refresh_,&QTimer::timeout,this,&TransportWatch::refresh);
    connect(&watcher_,&QFileSystemWatcher::directoryChanged,this,[this]{
        emit changed();if(!refresh_.isActive())refresh_.start();
    });
}
void TransportWatch::setFolder(const QString &folder) {
    if(folder_==folder)return;
    refresh_.stop();const auto old=watcher_.directories();if(!old.isEmpty())watcher_.removePaths(old);
    folder_=folder;refresh();
}
void TransportWatch::refresh() {
    if(folder_.isEmpty())return;
    QSet<QString> wanted;
    auto add=[&](const QString &path){
        auto component=path;
        for(int n=0;n<64;++n){
            const QFileInfo f(component);if(f.isSymLink())return;
            const auto parent=f.absolutePath();
            if(parent==component||QDir(component).isRoot()){
                if(QFileInfo(path).isDir())wanted.insert(path);return;
            }
            component=parent;
        }
    };
    // Keep an existing ancestor watched when a mount/root/events folder goes
    // away. Bounded and shallow; never traverse event contents or symlinks.
    auto ancestor=QFileInfo(folder_).absolutePath();
    for(int n=0;n<64;++n){
        if(QFileInfo(ancestor).isDir()){add(ancestor);break;}
        const auto parent=QFileInfo(ancestor).absolutePath();if(parent==ancestor)break;ancestor=parent;
    }
    add(folder_);const auto events=QDir(folder_).filePath("events");add(events);
    if(wanted.contains(events)){
        QDirIterator it(events,QDir::AllEntries|QDir::Hidden|QDir::System|QDir::NoDotAndDotDot);
        for(int n=0;n<128&&it.hasNext();++n)add(it.next());
    }
    const auto old=watcher_.directories();
    for(const auto &path:old)if(!wanted.remove(path))watcher_.removePath(path);
    if(!wanted.isEmpty())watcher_.addPaths(wanted.values());
}
} // namespace cqs::native
