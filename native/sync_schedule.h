// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <algorithm>
#include <cstdint>

namespace cqs::native {
// Monotonic milliseconds supplied by the owner; no wall clock or persisted
// deadlines. Restart always reconciles the durable record before doing work.
inline std::int64_t retryDelay(unsigned failures) {
    constexpr std::int64_t delays[]{1000,2000,4000,8000,16000,30000};
    return failures>6?60000:delays[failures?failures-1:0];
}
class SyncSchedule {
public:
    enum class Result { Success, Transient, Deferred, Conflict, Locked, Review };
    void reset(std::int64_t now) {
        running_=paused_=false;pending_=true;first_=-1;due_=now;poll_=now;retry_=0;failures_=0;
    }
    void changed(std::int64_t now) {
        if(first_<0)first_=now;
        pending_=true;due_=std::min(now+500,first_+2000);
    }
    bool begin(std::int64_t now) {
        if(delay(now)!=0)return false;
        running_=true;pending_=false;first_=-1;return true;
    }
    void finish(std::int64_t now,Result result) {
        running_=paused_=false;
        if(result==Result::Review){paused_=true;return;}
        if(result==Result::Transient){
            failures_=std::min(7u,failures_+1);retry_=now+retryDelay(failures_);poll_=retry_;return;
        }
        failures_=0;retry_=0;poll_=now+(result==Result::Deferred?2000:30000);
        // A locked vault is awakened by explicit unlock, not folder noise.
        if(result==Result::Locked){paused_=true;pending_=false;first_=-1;}
    }
    std::int64_t delay(std::int64_t now) const {
        if(running_||paused_)return 1000;
        return std::max<std::int64_t>(0,std::max(retry_,pending_?due_:poll_)-now);
    }
    bool paused() const { return paused_; }
private:
    bool running_=false,paused_=false,pending_=true;
    unsigned failures_=0;
    std::int64_t first_=-1,due_=0,poll_=0,retry_=0;
};
} // namespace cqs::native
