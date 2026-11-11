// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <QObject>
#include <QTimer>
#include <functional>
#include <memory>

class QThread;

namespace cqs::trust { enum class SignedReplicaResult; }

namespace cqs::native {

// One explicit in-memory opt-in for the running CopyQ process. All public
// methods and the guard/notification run on the owning Qt thread. Only Task
// runs on a worker and must not access UI objects or call back into the UI.
class SignedReplicaBackground final : public QObject {
public:
    enum class Access { Ready, Busy, Disarm };
    enum class State { Armed, Stopped, Conflict, Failed };
    using StillArmed = std::function<bool()>;
    using Task = std::function<trust::SignedReplicaResult(const StillArmed &)>;
    using Guard = std::function<Access()>;
    using Notify = std::function<void(State)>;

    explicit SignedReplicaBackground(QObject *parent = nullptr);
    ~SignedReplicaBackground() override;

    bool arm(Task task, Guard guard, Notify notify = {});
    bool armed() const;
    bool running() const;
    // Yield the checkpoint lease before opening the tab. The current work
    // must finish or cancel first. A later detached poll can resume.
    void pauseForLocalAccess();
    void stop();
    void shutdown();

private:
    struct Run;
    void dispatch();
    void complete(const std::shared_ptr<Run> &run);
    void cancelRun();
    void disarm(State state);

    QTimer timer_;
    Task task_;
    Guard guard_;
    Notify notify_;
    std::shared_ptr<Run> run_;
    std::unique_ptr<QThread> worker_;
    bool closed_ = false;
};

} // namespace cqs::native
