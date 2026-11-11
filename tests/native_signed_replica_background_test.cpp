// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_trust_journal.h"
#include "signed_replica_background.h"
#include "test_check.h"
#include <QCoreApplication>
#include <QDeadlineTimer>
#include <QThread>
#include <atomic>
#include <stdexcept>
#include <vector>

namespace {
using Background = cqs::native::SignedReplicaBackground;
using Access = Background::Access;
using State = Background::State;
using Result = cqs::trust::SignedReplicaResult;

template<class Predicate>
void waitFor(Predicate done) {
    QDeadlineTimer deadline(4000);
    while (!done() && !deadline.hasExpired()) {
        QCoreApplication::processEvents();
        QThread::msleep(1);
    }
    CHECK(done());
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    Background background;
    std::vector<State> states;
    const auto notify = [&](State state) {
        CHECK(QThread::currentThread() == app.thread());
        states.push_back(state);
    };
    std::atomic_int taskCalls{0};
    const auto success = [&](const Background::StillArmed &stillArmed) {
        CHECK(QThread::currentThread() != app.thread());
        CHECK(stillArmed());
        ++taskCalls;
        return Result::UpToDate;
    };
    const auto ready = [] { return Access::Ready; };
    CHECK(!background.arm({}, ready));
    CHECK(!background.arm(success, {}));
    CHECK(background.arm(success, ready, notify));
    CHECK(!background.arm(success, ready, notify));
    waitFor([&] { return taskCalls == 1 && !background.running(); });
    CHECK(background.armed());
    CHECK(states == std::vector<State>{State::Armed});
    background.stop();
    CHECK(!background.armed() && states.back() == State::Stopped);

    bool guardChecked = false;
    CHECK(background.arm(success, [&] {
        guardChecked = true;
        return Access::Busy;
    }, notify));
    waitFor([&] { return guardChecked; });
    CHECK(background.armed() && !background.running() && taskCalls == 1);
    background.stop();
    CHECK(background.arm(success, [] { return Access::Disarm; }, notify));
    waitFor([&] { return !background.armed(); });
    CHECK(taskCalls == 1 && states.back() == State::Stopped);
    CHECK(background.arm(success, []() -> Access { throw std::runtime_error("private data"); }, notify));
    waitFor([&] { return !background.armed(); });
    CHECK(taskCalls == 1 && states.back() == State::Failed);

    CHECK(background.arm([](const auto &) { return Result::Conflict; }, ready, notify));
    waitFor([&] { return !background.armed(); });
    CHECK(states.back() == State::Conflict);
    CHECK(background.arm([](const auto &) -> Result { throw std::runtime_error("private data"); }, ready, notify));
    waitFor([&] { return !background.armed(); });
    CHECK(states.back() == State::Failed);

    std::atomic_bool workerFinished{false};
    CHECK(background.arm([&](const auto &) {
        auto *thread = QThread::currentThread();
        QObject::connect(thread, &QThread::finished, thread, [&] { workerFinished = true; }, Qt::DirectConnection);
        return Result::Conflict;
    }, ready, notify));
    QCoreApplication::processEvents();
    QDeadlineTimer completion(4000);
    while (!workerFinished && !completion.hasExpired()) QThread::msleep(1);
    CHECK(workerFinished);
    background.pauseForLocalAccess();
    CHECK(!background.armed() && states.back() == State::Conflict);

    std::atomic_bool entered{false};
    std::atomic_bool exited{false};
    const auto cancellable = [&](const Background::StillArmed &stillArmed) {
        entered = true;
        QDeadlineTimer deadline(4000);
        while (stillArmed() && !deadline.hasExpired()) QThread::msleep(1);
        CHECK(!stillArmed());
        exited = true;
        return Result::Conflict; // A canceled completion must not disarm later work.
    };
    CHECK(background.arm(cancellable, ready, notify));
    waitFor([&] { return entered.load(); });
    background.pauseForLocalAccess();
    CHECK(exited && background.armed() && !background.running());
    QCoreApplication::processEvents();
    CHECK(background.armed() && states.back() == State::Armed);
    background.stop();

    entered = false;
    exited = false;
    CHECK(background.arm(cancellable, ready, notify));
    waitFor([&] { return entered.load(); });
    background.stop();
    CHECK(exited && !background.armed() && !background.running());
    CHECK(background.arm(success, ready, notify));
    waitFor([&] { return taskCalls == 2 && !background.running(); });
    CHECK(background.armed() && states.back() == State::Armed);

    background.shutdown();
    CHECK(!background.armed() && !background.running());
    CHECK(!background.arm(success, ready, notify));
}
