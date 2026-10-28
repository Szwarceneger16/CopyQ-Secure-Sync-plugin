// SPDX-License-Identifier: GPL-3.0-or-later
#include "inspector.h"
#include <QStringList>
#include <memory>
#include "key_reader.h"
#include "storage.h"

namespace cqs::native {
Inspector::~Inspector() {
    if (thread_) {
        // The worker performs bounded local I/O only; it never calls back into
        // CopyQ or waits on the GUI thread. Never terminate it unsafely.
        thread_->requestInterruption();
        thread_->wait();
    }
}
bool Inspector::request(const Profile &p, crypto::Bytes unlockedSyncKey) {
    if (busy()) return false;
    auto status = std::make_shared<QString>();
    struct Key { crypto::Bytes bytes; ~Key() { crypto::wipe(bytes); } };
    auto supplied=std::make_shared<Key>();supplied->bytes=std::move(unlockedSyncKey);
    thread_ = QThread::create([p, status, supplied] {
        try {
            const auto invalid = validateProfile(p, supplied->bytes.empty());
            if (!invalid.isEmpty()) { *status = invalid; return; }
            if(!p.vaultDirectory.isEmpty()&&supplied->bytes.empty())throw crypto::Error("Unlock the vault before inspection");
            Key key{supplied->bytes.empty()?readKeyStrict(std::filesystem::u8path(p.keyFile.toStdString())):supplied->bytes};
            if(key.bytes.size()!=32)throw crypto::Error("Invalid synchronization key");
            storage::Directory directory(std::filesystem::u8path(p.transport.toStdString()));
            if (QThread::currentThread()->isInterruptionRequested()) return;
            // The strict reader rejects symlinks, special files, unrecognized
            // conflict copies and mutations; never use QDir + ifstream here.
            auto history = directory.scan(key.bytes);
            if (QThread::currentThread()->isInterruptionRequested()) return;
            const auto tips=history.graph().tips().size();
            *status = QStringLiteral("Authenticated %1 event(s); %2 tip(s). %3\nRead only: no items, files or sync state changed.")
                .arg(static_cast<qulonglong>(history.graph().size())).arg(static_cast<qulonglong>(tips))
                .arg(history.graph().hasConflict() ? QStringLiteral("Conflict retained; use compare and resolve conflicts.")
                                                   : QStringLiteral("No conflict detected in this inspection."));
        } catch (const history::Error &e) {
            *status = e.code() == history::ErrorCode::MissingParent
                ? QStringLiteral("Waiting for referenced event files. No history is accepted and nothing is changed.")
                : QStringLiteral("History validation failed. Nothing is changed.");
        } catch (const events::Error &) {
            *status = QStringLiteral("Event authentication or payload validation failed. Nothing is changed.");
        } catch (const storage::Error &) {
            *status = QStringLiteral("Transport path, permissions, budget or stability check failed. Nothing is changed.");
        } catch (const crypto::Error &) {
            *status = QStringLiteral("K-SYNC cannot be read safely or is invalid. No key material is displayed.");
        } catch (...) {
            *status = QStringLiteral("Inspection failed. Nothing is changed; no file contents are logged.");
        }
    });
    auto *worker = thread_.data();
    worker->setParent(this);
    connect(worker, &QThread::finished, this, [this, worker, status] {
        if (thread_ == worker) thread_ = nullptr;
        worker->deleteLater();
        emit finished(status->isEmpty() ? QStringLiteral("Inspection cancelled.") : *status);
    });
    worker->start();
    return true;
}
} // namespace cqs::native
