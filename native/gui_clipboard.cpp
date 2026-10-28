// SPDX-License-Identifier: GPL-3.0-or-later
#include "gui_clipboard.h"
#include "packed_items.h"
#include <QScopeGuard>
namespace cqs::native {
transaction::Snapshot GuiClipboard::decode(const std::vector<std::string> &items,transaction::Limits limits){return packed::decode(items,limits);}
transaction::Snapshot GuiClipboard::persist(const transaction::View &view,transaction::Limits limits){
    if(!readDurable)throw ModelError(ModelErrorCode::PersistenceUnavailable);
    auto durable=readDurable(); // Authenticated disk read, on the worker.
    return dispatch_.call([this,view,limits,durable=std::move(durable)]() mutable {
        durable_=std::move(durable);const auto clear=qScopeGuard([this]{durable_.reset();});
        return model_->persist(view,limits);
    });
}
}
