// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "gui_dispatch.h"
#include "model_clipboard.h"

namespace cqs::native {
// Created/destroyed on the GUI thread. Only its transaction interface is called
// by the worker. The owner retains it until that worker has finished.
class GuiClipboard final : public transaction::Clipboard {
public:
    GuiClipboard(QObject *context,std::shared_ptr<OperationControl> control,QAbstractListModel *model,ModelAccess access)
        :dispatch_(context,std::move(control)) {
        access.persistAndReadback=[this](const transaction::View &,transaction::Limits){
            if(!durable_)throw ModelError(ModelErrorCode::PersistenceUnavailable);return *durable_;
        };
        model_=std::make_unique<ModelClipboard>(model,std::move(access));
    }
    transaction::Snapshot decode(const std::vector<std::string> &,transaction::Limits) override;
    transaction::View capture(transaction::Limits l) override {return dispatch_.call([this,l]{return model_->capture(l);});}
    void preflight(const transaction::View &v,const transaction::Snapshot &s) override {dispatch_.call([this,v,s]{model_->preflight(v,s);});}
    transaction::View replace(const transaction::View &v,const transaction::Snapshot &s) override {return dispatch_.call([this,v,s]{return model_->replace(v,s);});}
    transaction::Snapshot persist(const transaction::View &,transaction::Limits) override;
    // Installed and used solely by the worker; it never runs inside a GUI call.
    std::function<transaction::Snapshot()> readDurable;
private:
    GuiDispatch dispatch_;
    std::unique_ptr<ModelClipboard> model_;
    std::optional<transaction::Snapshot> durable_;
};
}
