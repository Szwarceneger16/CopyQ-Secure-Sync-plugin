// SPDX-License-Identifier: GPL-3.0-or-later
#include "signed_replica_background.h"
#include "device_trust_journal.h"
#include <QThread>
#include <atomic>
#include <utility>

namespace cqs::native {
namespace {
constexpr int PollMilliseconds = 30'000;
}

struct SignedReplicaBackground::Run {
    enum class Phase { Working, Cancelled, Completed };
    std::atomic<Phase> phase{Phase::Working};
    State result = State::Failed;
};

SignedReplicaBackground::SignedReplicaBackground(QObject *parent)
    : QObject(parent) {
    timer_.setSingleShot(true);
    connect(&timer_, &QTimer::timeout, this, &SignedReplicaBackground::dispatch);
}

SignedReplicaBackground::~SignedReplicaBackground() {
    shutdown();
}

bool SignedReplicaBackground::arm(Task task, Guard guard, Notify notify) {
    if (closed_ || armed() || !task || !guard) return false;
    task_ = std::move(task);
    guard_ = std::move(guard);
    notify_ = std::move(notify);
    timer_.start(0);
    if (notify_) {
        const auto callback = notify_;
        callback(State::Armed);
    }
    return true;
}

bool SignedReplicaBackground::armed() const {
    return bool(task_);
}

bool SignedReplicaBackground::running() const {
    return bool(worker_);
}

void SignedReplicaBackground::pauseForLocalAccess() {
    if (!running()) return;
    auto phase = Run::Phase::Working;
    if (!run_->phase.compare_exchange_strong(phase, Run::Phase::Cancelled)) {
        // Honor a completed conflict even before its queued notification.
        const auto run = run_;
        if (phase == Run::Phase::Completed) complete(run);
        return;
    }
    cancelRun();
    if (armed()) timer_.start(PollMilliseconds);
}

void SignedReplicaBackground::stop() {
    disarm(State::Stopped);
}

void SignedReplicaBackground::shutdown() {
    closed_ = true;
    notify_ = {};
    disarm(State::Stopped);
}

void SignedReplicaBackground::dispatch() {
    if (!armed() || running()) return;
    Access access;
    try {
        access = guard_();
    } catch (...) {
        disarm(State::Failed);
        return;
    }
    switch (access) {
    case Access::Disarm:
        disarm(State::Stopped);
        return;
    case Access::Busy:
        timer_.start(PollMilliseconds);
        return;
    case Access::Ready:
        break;
    }
    try {
        const auto run = std::make_shared<Run>();
        worker_.reset(QThread::create([run, task = task_] {
            const StillArmed stillArmed = [run] { return run->phase.load() == Run::Phase::Working; };
            try {
                if (!stillArmed()) return;
                switch (task(stillArmed)) {
                case trust::SignedReplicaResult::UpToDate:
                case trust::SignedReplicaResult::Pulled:
                case trust::SignedReplicaResult::Published:
                    run->result = State::Armed;
                    break;
                case trust::SignedReplicaResult::Conflict:
                    run->result = State::Conflict;
                    break;
                }
            } catch (...) {
                // Failure details can include a path or private profile data.
                // Report only a fixed state to the host.
            }
            auto phase = Run::Phase::Working;
            run->phase.compare_exchange_strong(phase, Run::Phase::Completed);
        }));
        run_ = run;
        connect(worker_.get(), &QThread::finished, this, [this, run] { complete(run); }, Qt::QueuedConnection);
        worker_->start();
        if (!worker_->isRunning() && !worker_->isFinished()) disarm(State::Failed);
    } catch (...) {
        disarm(State::Failed);
    }
}

void SignedReplicaBackground::complete(const std::shared_ptr<Run> &run) {
    // A queued completion can outlive stop or a later re-arm. The shared
    // token distinguishes it from any subsequent worker.
    if (run != run_) return;
    worker_->wait();
    worker_.reset();
    run_.reset();
    if (run->result == State::Armed)
        timer_.start(PollMilliseconds);
    else
        disarm(run->result);
}

void SignedReplicaBackground::cancelRun() {
    if (run_) run_->phase.store(Run::Phase::Cancelled);
    if (worker_) worker_->wait();
    worker_.reset();
    run_.reset();
}

void SignedReplicaBackground::disarm(State state) {
    timer_.stop();
    cancelRun();
    task_ = {};
    guard_ = {};
    const auto notify = std::move(notify_);
    if (notify) notify(state);
}

} // namespace cqs::native
