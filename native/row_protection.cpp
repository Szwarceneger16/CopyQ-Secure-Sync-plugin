// SPDX-License-Identifier: GPL-3.0-or-later
#include "row_protection.h"
#include "model_clipboard.h"
#include <QRegularExpression>
#include <algorithm>

namespace cqs::native {
namespace {
constexpr auto Pin="application/x-copyq-item-pinned";
constexpr auto Tags="application/x-copyq-tags";
QString unescape(QString s){return s.replace(";\\;",";;").replace("\\\\","\\");}
[[noreturn]] void refused(){throw ModelError(ModelErrorCode::ProtectedItems);}
}
RowProtection rowProtection(const QString &file,const QString &inventory){
    RowProtection p;p.pinned=inventory.split('\n').contains("PLUGIN itempinned: enabled");
    p.tags=inventory.split('\n').contains("PLUGIN itemtags: enabled");
    if(p.tags){QSettings s(file,QSettings::IniFormat);s.sync();if(s.status()!=QSettings::NoError)refused();p.definitions=s.value("Plugins/itemtags/tags").toStringList();}
    return p;
}
bool RowProtection::protects(const transaction::Item &item) const {
    if(pinned&&item.count(Pin))return true;
    const auto found=item.find(Tags);if(!tags||found==item.end())return false;
    const auto &v=found->second;
    const auto names=QString::fromUtf8(reinterpret_cast<const char *>(v.data()),qsizetype(v.size())).split(',',Qt::SkipEmptyParts);
    for(const auto &name:names)for(const auto &definition:definitions){
        const auto fields=definition.split(";;");const auto tag=unescape(fields.value(0)),regex=unescape(fields.value(4));
        // Same first-match, anchored regex and exact-name semantics as CopyQ 17.
        if(regex.isEmpty()?tag==name:QRegularExpression(QRegularExpression::anchoredPattern(regex)).match(name).hasMatch()){
            if(unescape(fields.value(5))=="L")return true;
            break;
        }
    }
    return false;
}
std::vector<std::pair<std::size_t,std::size_t>> RowProtection::anchors(const transaction::Snapshot &before,const transaction::Snapshot &after) const {
    std::vector<std::pair<std::size_t,std::size_t>> result;
    const auto prefix=pinnedPrefix(before);
    if(after.size()<prefix)refused();
    std::size_t next=0;
    for(std::size_t i=0;i<before.size();++i)if(protects(before[i])){
        if(i<prefix){if(after[i]!=before[i]||i<next)refused();result.emplace_back(i,i);next=i+1;continue;}
        // A cursor makes disjoint searches linear in rows. Exact MIME contents
        // distinguish protected duplicates without inventing an item UUID.
        while(next<after.size()&&after[next]!=before[i])++next;
        if(next==after.size())refused();
        result.emplace_back(i,next++);
    }
    return result;
}
std::size_t RowProtection::pinnedPrefix(const transaction::Snapshot &snapshot) const {
    std::size_t prefix=0;if(pinned)for(std::size_t i=0;i<snapshot.size();++i)if(snapshot[i].count(Pin))prefix=i+1;
    return prefix;
}
}
