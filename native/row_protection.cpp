// SPDX-License-Identifier: GPL-3.0-or-later
#include "row_protection.h"
#include "model_clipboard.h"
#include <QRegularExpression>
#include <algorithm>

namespace cqs::native {
namespace {
constexpr auto Pin="application/x-copyq-item-pinned";
constexpr auto Tags="application/x-copyq-tags";
constexpr std::size_t MaxTagBytesPerRow = 16 * 1024;
constexpr std::size_t MaxTagBytesPerSnapshot = 1024 * 1024;
constexpr std::size_t MaxTagNamesPerRow = 64;
constexpr std::size_t MaxTagNamesPerSnapshot = 16 * 1024;
constexpr std::size_t MaxTagNameBytes = 256;
constexpr std::size_t MaxTagComparisons = 128 * 1024;
constexpr std::size_t MaxRegexComparisons = 16 * 1024;
constexpr qsizetype MaxTagRules = 256;
constexpr qsizetype MaxDefinitionChars = 16 * 1024;
constexpr qsizetype MaxPatternChars = 1024;
QString unescape(QString s){return s.replace(";\\;",";;").replace("\\\\","\\");}
[[noreturn]] void refused(){throw ModelError(ModelErrorCode::ProtectedItems);}

struct TagBudget {
    std::size_t bytes = MaxTagBytesPerSnapshot;
    std::size_t names = MaxTagNamesPerSnapshot;
    std::size_t comparisons = MaxTagComparisons;
    std::size_t regexComparisons = MaxRegexComparisons;

    void account(const crypto::Bytes &value, std::size_t rules) {
        if (value.size() > MaxTagBytesPerRow || value.size() > bytes) refused();
        std::size_t count = 1;
        std::size_t length = 0;
        for (const auto byte : value) {
            if (byte == ',') {
                if (++count > MaxTagNamesPerRow) refused();
                length = 0;
            } else if (++length > MaxTagNameBytes) {
                refused();
            }
        }
        // Budget both the unmodified lock check and trimmed rendering check.
        if (count > names || (rules && count > comparisons / (2 * rules))) refused();
        bytes -= value.size();
        names -= count;
        comparisons -= count * (2 * rules);
    }
};

class TagMatcher {
public:
    explicit TagMatcher(const QStringList &definitions) {
        if (definitions.size() > MaxTagRules) refused();
        rules_.reserve(static_cast<std::size_t>(definitions.size()));
        for (const auto &definition : definitions) {
            if (definition.size() > MaxDefinitionChars) refused();
            const auto fields = definition.split(";;");
            const auto name = unescape(fields.value(0));
            const auto pattern = unescape(fields.value(4));
            if (pattern.size() > MaxPatternChars) refused();
            const auto locked = unescape(fields.value(5)) == "L";
            if (pattern.isEmpty()) {
                rules_.push_back({name, {}, false, locked});
                continue;
            }
            // Lower PCRE2's limits for locally configured expressions used
            // against peer-controlled subjects. Runtime match errors refuse.
            const QRegularExpression regex(QStringLiteral("(*NO_JIT)(*LIMIT_MATCH=2048)(*LIMIT_DEPTH=64)") +
                QRegularExpression::anchoredPattern(pattern));
            if (regex.isValid()) rules_.push_back({{}, regex, true, locked});
        }
    }

    bool inspect(const transaction::Item &item, TagBudget &budget) const {
        const auto found = item.find(Tags);
        if (found == item.end() || found->second.empty()) return false;
        const auto &value = found->second;
        budget.account(value, rules_.size());
        if (rules_.empty()) return false;
        const auto names = QString::fromUtf8(reinterpret_cast<const char *>(value.data()),
            static_cast<qsizetype>(value.size())).split(',', Qt::SkipEmptyParts);
        bool locked = false;
        for (const auto &name : names) {
            // Stock CopyQ uses the first matching definition and does not
            // trim for lock checks. Its renderer checks the trimmed name.
            if (matchesLocked(name, budget)) locked = true;
            const auto trimmed = name.trimmed();
            if (trimmed != name) (void)matchesLocked(trimmed, budget);
        }
        return locked;
    }

    void validate(const transaction::Snapshot &snapshot) const {
        TagBudget budget;
        for (const auto &item : snapshot) (void)inspect(item, budget);
    }

private:
    struct Rule {
        QString name;
        QRegularExpression regex;
        bool usesRegex;
        bool locked;
    };
    std::vector<Rule> rules_;

    bool matchesLocked(const QString &name, TagBudget &budget) const {
        for (const auto &rule : rules_) {
            if (!rule.usesRegex) {
                if (name == rule.name) return rule.locked;
                continue;
            }
            if (!budget.regexComparisons) refused();
            --budget.regexComparisons;
            const auto match = rule.regex.match(name);
            if (!match.isValid()) refused();
            if (match.hasMatch()) return rule.locked;
        }
        return false;
    }
};
}
RowProtection rowProtection(const QString &file,const QString &inventory){
    RowProtection p;p.pinned=inventory.split('\n').contains("PLUGIN itempinned: enabled");
    p.tags=inventory.split('\n').contains("PLUGIN itemtags: enabled");
    if(p.tags){QSettings s(file,QSettings::IniFormat);s.sync();if(s.status()!=QSettings::NoError)refused();p.definitions=s.value("Plugins/itemtags/tags").toStringList();}
    return p;
}
bool RowProtection::protects(const transaction::Item &item) const {
    TagBudget budget;
    const bool locked = tags && TagMatcher(definitions).inspect(item, budget);
    return locked || (pinned && item.count(Pin));
}
void RowProtection::validateTags(const transaction::Snapshot &snapshot) const {
    TagMatcher(tags ? definitions : QStringList{}).validate(snapshot);
}
std::vector<std::pair<std::size_t,std::size_t>> RowProtection::anchors(const transaction::Snapshot &before,const transaction::Snapshot &after) const {
    std::vector<std::pair<std::size_t,std::size_t>> result;
    const TagMatcher matcher(tags ? definitions : QStringList{});
    // Apply structural bounds even with itemtags disabled. A later settings
    // change can enable its renderer for the same model.
    matcher.validate(after);
    TagBudget budget;
    const auto prefix=pinnedPrefix(before);
    if(after.size()<prefix)refused();
    std::size_t next=0;
    for(std::size_t i=0;i<before.size();++i){
        const bool locked = matcher.inspect(before[i], budget);
        if (!locked && !(pinned && before[i].count(Pin))) continue;
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
