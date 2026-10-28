// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <QFileDevice>
#include <QFileInfo>
#include <QSaveFile>
#include <QTemporaryFile>
#include <memory>
#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <io.h>
#else
#include <cerrno>
#include <unistd.h>
#endif

namespace copyq::sync {
inline bool flushFileToDisk(QFileDevice &file) {
    if (!file.flush()) return false;
#ifdef Q_OS_WIN
    const auto handle = _get_osfhandle(file.handle());
    return handle != -1 && FlushFileBuffers(reinterpret_cast<HANDLE>(handle));
#else
    int result;
    do { result = ::fsync(file.handle()); } while (result == -1 && errno == EINTR);
    return result == 0;
#endif
}
// The bridge owns this operation, rather than committing a device borrowed from
// a saver callback. On Windows Qt does not request MOVEFILE_WRITE_THROUGH.
class VerifiedSaveFile final {
public:
    explicit VerifiedSaveFile(const QString &path)
#ifdef Q_OS_WIN
        : file_(std::make_unique<QTemporaryFile>(path + ".cqs-XXXXXX")),
          destination_(QFileInfo(path).absoluteFilePath()) {}
#else
        : file_(path) { file_.setDirectWriteFallback(false); }
#endif
    bool open() {
#ifdef Q_OS_WIN
        return file_ && file_->open();
#else
        return file_.open(QIODevice::WriteOnly);
#endif
    }
    QFileDevice &device() {
#ifdef Q_OS_WIN
        return *file_;
#else
        return file_;
#endif
    }
    void cancelWriting() {
#ifndef Q_OS_WIN
        file_.cancelWriting();
#endif
    }
    bool commit() {
#ifdef Q_OS_WIN
        if (!file_ || !file_->isOpen() || !file_->flush() || file_->error() != QFileDevice::NoError)
            return false;
        const auto temporary = file_->fileName().toStdWString();
        // Keep an encrypted orphan on any ambiguous native rename failure.
        // No post-attempt cleanup ever removes the authoritative destination.
        file_->setAutoRemove(false);
        // QTemporaryFile::close() only rewinds its native file engine. Its
        // Windows handle lacks FILE_SHARE_DELETE and prevents MoveFileExW.
        // Destroy the owner to really close that handle before replacement.
        file_.reset();
        const auto destination = destination_.toStdWString();
        return MoveFileExW(temporary.c_str(), destination.c_str(),
                           MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
#else
        return file_.commit();
#endif
    }
private:
#ifdef Q_OS_WIN
    std::unique_ptr<QTemporaryFile> file_;
    QString destination_;
#else
    QSaveFile file_;
#endif
};
} // namespace copyq::sync
