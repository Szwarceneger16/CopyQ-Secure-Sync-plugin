// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <QObject>
#include <QMetaObject>
#include <QThread>
#include <condition_variable>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <type_traits>

namespace cqs::native {
class Cancelled final : public std::runtime_error {
public: Cancelled():std::runtime_error("Operation cancelled; reload durable state"){}
};
// The GUI owner cancels before joining its worker. A queued request may then be
// discarded without running it, so shutdown never needs to pump Qt events.
class OperationControl final {
public:
    void cancel(){std::lock_guard<std::mutex> lock(mutex_);cancelled_=true;condition_.notify_all();}
    void check() const {std::lock_guard<std::mutex> lock(mutex_);if(cancelled_)throw Cancelled();}
private:
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    bool cancelled_=false;
    friend class GuiDispatch;
};
class GuiDispatch final {
public:
    // context must outlive the worker; its destructor cancels, then joins.
    GuiDispatch(QObject *context,std::shared_ptr<OperationControl> control):context_(context),control_(std::move(control)){}
    template<class F> auto call(F function) const -> std::invoke_result_t<F> {
        using Result=std::invoke_result_t<F>;
        using Value=std::conditional_t<std::is_void_v<Result>,bool,Result>;
        struct Request {std::optional<Value> result;std::exception_ptr error;bool done=false;};
        control_->check();
        if(QThread::currentThread()==context_->thread())throw std::logic_error("GUI dispatch called from GUI thread");
        auto request=std::make_shared<Request>();auto control=control_;
        if(!QMetaObject::invokeMethod(context_,[request,control,function=std::move(function)]() mutable {
            try {
                control->check();
                if constexpr(std::is_void_v<Result>){function();request->result=true;}
                else request->result=function();
            }catch(...){request->error=std::current_exception();}
            std::lock_guard<std::mutex> lock(control->mutex_);request->done=true;control->condition_.notify_all();
        },Qt::QueuedConnection))throw Cancelled();
        std::unique_lock<std::mutex> lock(control_->mutex_);
        control_->condition_.wait(lock,[&]{return request->done||control_->cancelled_;});
        if(control_->cancelled_)throw Cancelled();
        if(request->error)std::rethrow_exception(request->error);
        if constexpr(!std::is_void_v<Result>)return std::move(*request->result);
    }
private:
    QObject *context_;
    std::shared_ptr<OperationControl> control_;
};
}
