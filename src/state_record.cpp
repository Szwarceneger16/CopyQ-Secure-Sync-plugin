// SPDX-License-Identifier: GPL-3.0-or-later
#include "state_record.h"
#include <algorithm>
#include <limits>
#include <utility>

namespace cqs::state {
namespace {
using crypto::Bytes;
using namespace transaction;
[[noreturn]] void fail(ErrorCode c, const char *s) { throw Error(c, s); }
constexpr char Magic[] = "CQSREC01";
constexpr std::size_t PackedLimit = 32 * 1024 * 1024;
struct Wiped { Bytes bytes; ~Wiped() { crypto::wipe(bytes); } };
void checkKey(const Bytes &key) {
    if (key.size() != 32) fail(ErrorCode::InvalidKey, "Private record key must have 32 bytes");
}
void add(std::size_t &used, std::size_t n, std::size_t maximum) {
    if (n > maximum - used) fail(ErrorCode::SizeLimit, "Private record exceeds resource limit");
    used += n;
}
void mime(const std::string &name, Limits limits) {
    if (name.empty() || name.size() > limits.snapshot.mimeNameBytes ||
        !std::all_of(name.begin(), name.end(), [](unsigned char c) { return c >= 0x21 && c <= 0x7e; }))
        fail(ErrorCode::InvalidRecord, "Invalid private snapshot MIME name");
}
int sextet(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    return c == '+' ? 62 : c == '/' ? 63 : -1;
}
void packed(const std::string &s) {
    if (s.size() % 4) fail(ErrorCode::InvalidRecord, "Invalid stored base64");
    if (s.empty()) return;
    const auto n = s.size();
    const std::size_t pad = s[n-1] == '=' ? (s[n-2] == '=' ? 2 : 1) : 0;
    for (std::size_t i = 0; i < n - pad; ++i)
        if (sextet(s[i]) < 0) fail(ErrorCode::InvalidRecord, "Invalid stored base64");
    if ((pad == 2 && (sextet(s[n-3]) & 15)) || (pad == 1 && (sextet(s[n-2]) & 3)))
        fail(ErrorCode::InvalidRecord, "Noncanonical stored base64");
}
void revision(const history::Revision &r) {
    try { history::validateRevision(r); }
    catch (const history::Error &) { fail(ErrorCode::InvalidRecord, "Invalid stored revision"); }
}
void relationships(const Record &r) {
    if (r.schema < 1 || r.schema > 6) fail(ErrorCode::InvalidRecord, "Unknown private record schema");
    if(r.schema<6&&!r.witnessed.empty())fail(ErrorCode::InvalidRecord,"History witnesses require schema 6");
    if(r.witnessed.size()>history::MaxEvents)fail(ErrorCode::SizeLimit,"History witness capacity reached");
    for(const auto &entry:r.witnessed){
        const auto slash=entry.first.find('/');
        try{history::validateRevision({entry.first,entry.first.substr(0,slash),std::stoull(entry.first.substr(slash+1)),{}});}
        catch(const std::exception &){fail(ErrorCode::InvalidRecord,"Invalid witnessed identity");}
        if(entry.second.size()!=32)fail(ErrorCode::InvalidRecord,"Invalid witnessed fingerprint");
    }
    if(r.schema<5&&(!r.archives.empty()||r.resolution))fail(ErrorCode::InvalidRecord,"Resolution requires schema 5");
    if(r.archives.size()>4)fail(ErrorCode::SizeLimit,"Conflict archive capacity reached");
    if(r.resolution){
        if(!r.head||r.archives.empty()||r.resolution->tips.empty()||r.resolution->tips.size()>history::MaxEvents)
            fail(ErrorCode::InvalidRecord,"Invalid resolution context");
        std::string previous;for(const auto &id:r.resolution->tips){
            try{const auto slash=id.find('/');history::validateRevision({id,id.substr(0,slash),std::stoull(id.substr(slash+1)),{}});}catch(const std::exception &){fail(ErrorCode::InvalidRecord,"Invalid resolution tip");}
            if(!previous.empty()&&id<=previous)fail(ErrorCode::InvalidRecord,"Unsorted resolution tips");
            previous=id;
        }
    }
    if(r.schema < 3 && (r.allocatedSequence || r.publication || r.preserved))
        fail(ErrorCode::InvalidRecord,"Outbound fields require schema 3");
    if(r.allocatedSequence > history::MaxSequence)fail(ErrorCode::InvalidRecord,"Invalid outbound sequence");
    if(r.publication){
        const auto &p=*r.publication;const auto &rev=p.target.event.revision;
        if(r.resolution&&rev.parents.empty())fail(ErrorCode::InvalidRecord,"Resolution must extend history");
        if(r.pending || !r.allocatedSequence || !r.generation || p.wire.empty() ||
           p.wire.size()>events::Limits{}.eventBytes || rev.sequence!=r.allocatedSequence)
            fail(ErrorCode::InvalidRecord,"Invalid publication intent");
        if(r.head){
            if(r.schema<4 || (!r.resolution&&rev.parents!=std::vector<std::string>{r.head->event.revision.id}) ||
               rev.id==r.head->event.revision.id)
                fail(ErrorCode::InvalidRecord,"Publication must extend the retained head");
            if(r.resolution)for(const auto &parent:rev.parents)
                if(std::find(r.resolution->tips.begin(),r.resolution->tips.end(),parent)==r.resolution->tips.end())
                    fail(ErrorCode::InvalidRecord,"Resolution parent outside confirmed tips");
            if(r.resolution&&rev.parents.size()!=std::min(std::size_t{2},r.resolution->tips.size()))
                fail(ErrorCode::InvalidRecord,"Resolution must join confirmed tips");
        }else if(!rev.parents.empty() || rev.sequence!=1)
            fail(ErrorCode::InvalidRecord,"Invalid Seed publication intent");
    }
    if (r.schema == 1 ? (r.local.has_value() || !r.keyIdentity.empty()) :
        (!r.local || r.keyIdentity.size() != 64 || !std::all_of(r.keyIdentity.begin(), r.keyIdentity.end(),
            [](unsigned char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');})))
        fail(ErrorCode::InvalidRecord, "Private record schema/context mismatch");
    validateBinding(r.binding);
    if (!r.generation && (r.head || r.pending))
        fail(ErrorCode::InvalidRecord, "Generation zero must be unjoined");
    if (r.pending) {
        if(r.resolution&&(r.resolution->tips!=std::vector<std::string>{r.head->event.revision.id}||
            r.pending->target.event.revision.id!=r.head->event.revision.id||
            r.pending->target.event.items!=r.head->event.items||
            r.pending->target.event.revision.parents!=r.head->event.revision.parents||
            r.pending->target.snapshot!=r.head->snapshot||r.pending->original!=r.archives.back()))
            fail(ErrorCode::InvalidRecord,"Projection must match the accepted resolution and backup");
        if (r.pending->phase != Phase::Import && r.pending->phase != Phase::Restore)
            fail(ErrorCode::InvalidRecord, "Unknown recovery phase");
        const Snapshot empty;
        if (r.pending->original != (r.head ? r.head->snapshot : empty) &&
            (r.head || !r.preserved || r.pending->original!=*r.preserved) &&
            (!r.resolution || r.archives.empty() || r.pending->original!=r.archives.back()))
            fail(ErrorCode::InvalidRecord, "Backup disagrees with prior checkpoint");
        if (r.head && !r.resolution && r.head->event.revision.id == r.pending->target.event.revision.id)
            fail(ErrorCode::InvalidRecord, "Pending target reuses checkpoint identity");
    }
}
class Writer {
public:
    explicit Writer(Limits limits) : limits_(limits) {}
    ~Writer() { crypto::wipe(out_); }
    void u64(std::uint64_t v) {
        room(8); for (int shift = 56; shift >= 0; shift -= 8) out_.push_back(static_cast<std::uint8_t>(v >> shift));
    }
    void flag(unsigned v) { room(1); out_.push_back(static_cast<std::uint8_t>(v)); }
    template<class T> void bytes(const T &v, std::size_t maximum) {
        if (v.size() > maximum) fail(ErrorCode::SizeLimit, "Private field exceeds limit");
        u64(v.size()); room(v.size()); out_.insert(out_.end(), v.begin(), v.end());
    }
    void snapshot(const Snapshot &s) {
        if (s.size() > limits_.snapshot.items) fail(ErrorCode::SizeLimit, "Too many snapshot items");
        u64(s.size()); std::size_t total = 0;
        for (const auto &item : s) {
            if (item.size() > limits_.snapshot.formatsPerItem) fail(ErrorCode::SizeLimit, "Too many MIME formats");
            u64(item.size());
            for (const auto &entry : item) {
                mime(entry.first, limits_);
                add(total, entry.first.size(), limits_.snapshot.snapshotBytes);
                add(total, entry.second.size(), limits_.snapshot.snapshotBytes);
                bytes(entry.first, limits_.snapshot.mimeNameBytes);
                bytes(entry.second, limits_.snapshot.snapshotBytes);
            }
        }
    }
    void head(const Head &h) {
        const auto &r = h.event.revision; revision(r);
        bytes(r.id, 45); bytes(r.device, 32); u64(r.sequence);
        u64(r.parents.size()); for (const auto &p : r.parents) bytes(p, 45);
        if (h.event.plaintextBytes > PackedLimit) fail(ErrorCode::SizeLimit, "Stored event size exceeds limit");
        u64(h.event.plaintextBytes);
        if (h.event.items.size() > limits_.snapshot.items || h.event.items.size() != h.snapshot.size())
            fail(ErrorCode::InvalidRecord, "Event and snapshot item counts disagree");
        u64(h.event.items.size()); std::size_t total = 0;
        for (const auto &item : h.event.items) {
            add(total, item.size(), PackedLimit); packed(item); bytes(item, PackedLimit);
        }
        snapshot(h.snapshot);
    }
    Bytes take() { return std::move(out_); }
private:
    void room(std::size_t n) {
        if (n > limits_.recordBytes - out_.size()) fail(ErrorCode::SizeLimit, "Aggregate private record exceeds limit");
    }
    Limits limits_; Bytes out_;
};
class Reader {
public:
    Reader(const Bytes &b, Limits l) : in_(b), limits_(l) {}
    std::uint64_t u64() {
        need(8); std::uint64_t n = 0; for (int i = 0; i < 8; ++i) n = (n << 8) | in_[pos_++]; return n;
    }
    unsigned flag() { need(1); auto v = in_[pos_++]; if (v > 1) fail(ErrorCode::InvalidRecord, "Invalid record flag"); return v; }
    std::size_t count(std::size_t maximum, std::size_t minimumBytes = 0) {
        auto n = u64();
        if (n > maximum || (minimumBytes && n > (in_.size()-pos_) / minimumBytes))
            fail(ErrorCode::SizeLimit, "Private record count exceeds bounds");
        return static_cast<std::size_t>(n);
    }
    template<class T> T bytes(std::size_t maximum) {
        auto n = count(maximum); need(n);
        T value(in_.begin() + pos_, in_.begin() + pos_ + n); pos_ += n; return value;
    }
    Snapshot snapshot() {
        const auto n = count(limits_.snapshot.items, 8); Snapshot out; out.reserve(n); std::size_t total = 0;
        for (std::size_t i = 0; i < n; ++i) {
            const auto formats = count(limits_.snapshot.formatsPerItem, 17); Item item; std::string previous;
            for (std::size_t j = 0; j < formats; ++j) {
                auto name = bytes<std::string>(std::min(limits_.snapshot.mimeNameBytes, limits_.snapshot.snapshotBytes-total));
                mime(name, limits_); add(total, name.size(), limits_.snapshot.snapshotBytes);
                if (j && name <= previous) fail(ErrorCode::InvalidRecord, "Duplicate or unsorted MIME field");
                previous = name;
                auto value = bytes<Bytes>(limits_.snapshot.snapshotBytes-total);
                add(total, value.size(), limits_.snapshot.snapshotBytes);
                item.emplace(std::move(name), std::move(value));
            }
            out.push_back(std::move(item));
        }
        return out;
    }
    Head head() {
        Head out; auto &r = out.event.revision;
        r.id = bytes<std::string>(45); r.device = bytes<std::string>(32); r.sequence = u64();
        auto n = count(2, 8); for (std::size_t i = 0; i < n; ++i) r.parents.push_back(bytes<std::string>(45));
        revision(r);
        out.event.plaintextBytes = count(PackedLimit);
        n = count(limits_.snapshot.items, 8); out.event.items.reserve(n); std::size_t total = 0;
        for (std::size_t i = 0; i < n; ++i) {
            auto item = bytes<std::string>(PackedLimit-total); add(total, item.size(), PackedLimit); packed(item);
            out.event.items.push_back(std::move(item));
        }
        out.snapshot = snapshot();
        if (out.event.items.size() != out.snapshot.size()) fail(ErrorCode::InvalidRecord, "Stored item counts disagree");
        return out;
    }
    void end() { if (pos_ != in_.size()) fail(ErrorCode::InvalidRecord, "Trailing private record data"); }
private:
    void need(std::size_t n) { if (n > in_.size()-pos_) fail(ErrorCode::InvalidRecord, "Truncated private record"); }
    const Bytes &in_; Limits limits_; std::size_t pos_ = 0;
};
Bytes aad(const std::string &binding) {
    constexpr char domain[] = "CopyQ-Secure-Sync-private-state-v1";
    Bytes out(domain, domain + sizeof(domain)); // includes NUL; differs from event AAD
    out.insert(out.end(), Magic, Magic + 8);
    out.insert(out.end(), binding.begin(), binding.end());
    return out;
}
} // namespace
void validateLimits(Limits l) {
    const Limits max;
    if (!l.recordBytes || l.recordBytes > max.recordBytes || l.snapshot.items > max.snapshot.items ||
        !l.snapshot.formatsPerItem || l.snapshot.formatsPerItem > max.snapshot.formatsPerItem ||
        !l.snapshot.mimeNameBytes || l.snapshot.mimeNameBytes > max.snapshot.mimeNameBytes ||
        !l.snapshot.snapshotBytes || l.snapshot.snapshotBytes > max.snapshot.snapshotBytes)
        fail(ErrorCode::InvalidLimits, "Invalid private record limits");
}
void validateBinding(const std::string &b) {
    if (b.empty() || b.size() > 128 || !std::all_of(b.begin(), b.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
    })) fail(ErrorCode::WrongBinding, "Invalid private record binding");
}
Bytes serialize(const Record &r, Limits limits) {
    validateLimits(limits); relationships(r); Writer w(limits);
    w.u64(r.schema); w.bytes(r.binding, 128); w.u64(r.generation);
    w.flag(r.head.has_value()); if (r.head) w.head(*r.head);
    w.flag(r.pending.has_value());
    if (r.pending) { w.flag(r.pending->phase == Phase::Restore); w.head(r.pending->target); w.snapshot(r.pending->original); }
    if (r.schema >= 2) { w.snapshot(*r.local); w.bytes(r.keyIdentity, 64); }
    if (r.schema >= 3) {
        w.u64(r.allocatedSequence);w.flag(r.publication.has_value());
        if(r.publication){w.head(r.publication->target);w.bytes(r.publication->wire,events::Limits{}.eventBytes);}
        w.flag(r.preserved.has_value());if(r.preserved)w.snapshot(*r.preserved);
    }
    if(r.schema>=5){w.u64(r.archives.size());for(const auto &s:r.archives)w.snapshot(s);
        w.flag(r.resolution.has_value());if(r.resolution){w.u64(r.resolution->tips.size());for(const auto &id:r.resolution->tips)w.bytes(id,45);}}
    if(r.schema>=6){w.u64(r.witnessed.size());for(const auto &entry:r.witnessed){w.bytes(entry.first,45);w.bytes(entry.second,32);}}
    return w.take();
}
Record parse(const Bytes &plain, Limits limits) {
    validateLimits(limits);
    if (plain.size() > limits.recordBytes) fail(ErrorCode::SizeLimit, "Private record exceeds limit");
    Reader r(plain, limits); Record out;
    const auto schema = r.u64();
    if (schema < 1 || schema > 6) fail(ErrorCode::InvalidRecord, "Unknown private record schema");
    out.schema = unsigned(schema);
    out.binding = r.bytes<std::string>(128); validateBinding(out.binding); out.generation = r.u64();
    if (r.flag()) out.head = r.head();
    if (r.flag()) {
        Pending p; p.phase = r.flag() ? Phase::Restore : Phase::Import;
        p.target = r.head(); p.original = r.snapshot(); out.pending = std::move(p);
    }
    if(out.schema >= 2) { out.local = r.snapshot(); out.keyIdentity = r.bytes<std::string>(64); }
    if(out.schema >= 3){out.allocatedSequence=r.u64();
        if(r.flag()){Publication p;p.target=r.head();p.wire=r.bytes<std::string>(events::Limits{}.eventBytes);out.publication=std::move(p);}
        if(r.flag())out.preserved=r.snapshot();
    }
    if(out.schema>=5){const auto n=r.count(4,8);for(std::size_t i=0;i<n;++i)out.archives.push_back(r.snapshot());
        if(r.flag()){Resolution resolution;const auto tips=r.count(history::MaxEvents,8);for(std::size_t i=0;i<tips;++i)resolution.tips.push_back(r.bytes<std::string>(45));out.resolution=std::move(resolution);}}
    if(out.schema>=6){const auto n=r.count(history::MaxEvents,16);std::string previous;
        for(std::size_t i=0;i<n;++i){auto id=r.bytes<std::string>(45);auto fingerprint=r.bytes<Bytes>(32);
            if(!previous.empty()&&id<=previous)fail(ErrorCode::InvalidRecord,"Unsorted history witnesses");
            previous=id;out.witnessed.emplace(std::move(id),std::move(fingerprint));}}
    r.end(); relationships(out); return out;
}
void validateSecret(const Bytes &secret, Protection protection) {
    if (protection == Protection::Key) checkKey(secret);
    else if (protection != Protection::Password || secret.empty() || secret.size() > 1024)
        fail(ErrorCode::InvalidKey, "Invalid vault password length");
}
Bytes seal(const Bytes &secret, const std::string &binding, const Record &r, Limits limits, Protection protection) {
    validateLimits(limits); validateBinding(binding); validateSecret(secret, protection);
    if (r.binding != binding) fail(ErrorCode::WrongBinding, "Record belongs to another binding");
    Wiped plain{serialize(r, limits)}; const auto nonce = crypto::random(12);
    Bytes header; Wiped derived;
    auto authentication = aad(binding);
    if (protection == Protection::Password) {
        constexpr char magic[] = "CQSVLT01";
        header.assign(magic, magic + 8);
        const auto salt = crypto::random(16); header.insert(header.end(), salt.begin(), salt.end());
        for (int shift = 24; shift >= 0; shift -= 8) header.push_back(std::uint8_t(PasswordIterations >> shift));
        derived.bytes = crypto::passwordKey(secret, salt, PasswordIterations);
    } else header.assign(Magic, Magic + 8);
    header.insert(header.end(), nonce.begin(), nonce.end());
    if (protection == Protection::Password) authentication.insert(authentication.end(), header.begin(), header.end());
    const auto cipher = crypto::aes256GcmEncrypt(protection == Protection::Password ? derived.bytes : secret,
                                               nonce, plain.bytes, authentication);
    header.insert(header.end(), cipher.begin(), cipher.end()); return header;
}
Record unseal(const Bytes &secret, const std::string &binding, const Bytes &wire, Limits limits, Protection protection) {
    validateLimits(limits); validateBinding(binding); validateSecret(secret, protection);
    const auto overhead = envelopeOverhead(protection);
    if (wire.size() > limits.recordBytes + overhead) fail(ErrorCode::SizeLimit, "Private envelope exceeds limit");
    constexpr char passwordMagic[] = "CQSVLT01";
    const auto *magic = protection == Protection::Password ? passwordMagic : Magic;
    if (wire.size() < overhead || !std::equal(magic, magic + 8, wire.begin()))
        fail(ErrorCode::InvalidRecord, "Unknown or truncated private envelope");
    Wiped derived; std::size_t nonceOffset = 8;
    auto authentication = aad(binding);
    if (protection == Protection::Password) {
        unsigned iterations = 0;
        for (int i = 24; i < 28; ++i) iterations = (iterations << 8) | wire[i];
        if (iterations != PasswordIterations) fail(ErrorCode::InvalidRecord, "Unsupported vault derivation parameters");
        derived.bytes = crypto::passwordKey(secret, Bytes(wire.begin() + 8, wire.begin() + 24), iterations);
        nonceOffset = 28;
        authentication.insert(authentication.end(), wire.begin(), wire.begin() + nonceOffset + 12);
    }
    const Bytes nonce(wire.begin() + nonceOffset, wire.begin() + nonceOffset + 12), cipher(wire.begin() + nonceOffset + 12, wire.end());
    Wiped plain;
    try { plain.bytes = crypto::aes256GcmDecrypt(protection == Protection::Password ? derived.bytes : secret, nonce, cipher, authentication); }
    catch (const crypto::Error &) { fail(ErrorCode::AuthenticationFailed, "Private record authentication failed"); }
    auto out = parse(plain.bytes, limits);
    if (out.binding != binding) fail(ErrorCode::WrongBinding, "Private record binding mismatch");
    return out;
}
} // namespace cqs::state
