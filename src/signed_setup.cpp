// SPDX-License-Identifier: GPL-3.0-or-later
#include "signed_setup.h"
#include "device_identity_vault.h"
#include "device_key_envelope.h"
#include "storage.h"
#include <algorithm>
#include <array>
#include <limits>
#include <utility>
#ifdef _WIN32
#include "windows_state_path.h"
#include <windows.h>
#include <sddl.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace cqs::trust {
namespace {
using crypto::Bytes;
constexpr auto Mime = "application/x-copyq-secure-sync-signed-setup-v1";
constexpr auto InvitePrefix = "cqs-signed-group-v1/";
constexpr std::size_t GenesisBytes = 192;

[[noreturn]] void refuse() {
    throw state::Error(state::ErrorCode::InvalidRecord, "Signed setup is unavailable or does not match this profile");
}
[[noreturn]] void unsafe() {
    throw state::Error(state::ErrorCode::UnsafePath, "Signed setup requires dedicated safe local directories");
}
struct Wiped {
    Bytes bytes;
    ~Wiped() { crypto::wipe(bytes); }
};
struct PrivateRecord {
    transaction::Record value;
    ~PrivateRecord() {
        if (value.local) for (auto &item : *value.local) for (auto &field : item) crypto::wipe(field.second);
    }
};
std::string hex(const Bytes &bytes) {
    constexpr char Digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(2 * bytes.size());
    for (const auto value : bytes) {
        result.push_back(Digits[value >> 4]);
        result.push_back(Digits[value & 15]);
    }
    return result;
}
Bytes unhex(const std::string &text) {
    if (text.size() != 2 * GenesisBytes) refuse();
    Bytes result;
    result.reserve(GenesisBytes);
    const auto digit = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return unsigned(c - '0');
        if (c >= 'a' && c <= 'f') return unsigned(c - 'a' + 10);
        refuse();
    };
    for (std::size_t i = 0; i < text.size(); i += 2)
        result.push_back(std::uint8_t((digit(text[i]) << 4) | digit(text[i + 1])));
    return result;
}
template<class Range> void append(Bytes &out, const Range &value) {
    out.insert(out.end(), value.begin(), value.end());
}
void number(Bytes &out, std::uint64_t value) {
    for (unsigned shift = 64; shift; shift -= 8) out.push_back(std::uint8_t(value >> (shift - 8)));
}
void blob(Bytes &out, const Bytes &bytes) { number(out, bytes.size()); append(out, bytes); }
Bytes publicGenesis(const Genesis &genesis) {
    if (genesis.group == Token{} || genesis.recovery == Token{} || genesis.initialKeyCommitment == Token{} ||
        !SodiumVerifier::validMember(genesis.founder)) refuse();
    const Membership validate(genesis.group, genesis.founder, genesis.recovery, genesis.initialKeyCommitment);
    (void)validate;
    Bytes result;
    for (const auto *field : {&genesis.group, &genesis.founder.id, &genesis.founder.signingKey,
                              &genesis.founder.encryptionKey, &genesis.recovery, &genesis.initialKeyCommitment})
        append(result, *field);
    return result;
}
Token randomToken() {
    const auto bytes = crypto::random(32);
    Token result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    if (result == Token{}) refuse();
    return result;
}
std::filesystem::path checkedPath(const std::filesystem::path &path) {
    const auto text = path.generic_u8string();
    if (!path.is_absolute() || path == path.root_path() || path.lexically_normal() != path || text.size() > 4096 ||
        text.find(char(0)) != std::string::npos || text.compare(0, 2, "//") == 0 ||
        std::any_of(text.begin(), text.end(), [](unsigned char c) { return c < 32 || c == 127; })) unsafe();
    return path;
}
bool overlaps(const std::filesystem::path &a, const std::filesystem::path &b) {
#ifdef _WIN32
    const auto x = a.generic_wstring(), y = b.generic_wstring();
    const auto prefix = [](const std::wstring &value, const std::wstring &start) {
        return value.size() >= start.size() &&
            CompareStringOrdinal(value.data(), int(start.size()), start.data(), int(start.size()), TRUE) == CSTR_EQUAL;
    };
    return (x.size() == y.size() && prefix(x, y)) || prefix(x, y + L'/') || prefix(y, x + L'/');
#else
    const auto x = a.generic_u8string(), y = b.generic_u8string();
    return x == y || x.compare(0, y.size() + 1, y + '/') == 0 || y.compare(0, x.size() + 1, x + '/') == 0;
#endif
}
std::string setupBinding(const std::filesystem::path &root) {
    const auto text = root.generic_u8string();
    Bytes input{'C','q','s','S','i','g','n','e','d','S','e','t','u','p',0};
    append(input, text);
    return "signed-setup-" + hex(crypto::sha256(input));
}

// Names supplied to this helper are locally generated single components.
// Keep every ancestor pinned while creating the directory and refuse links.
class DirectoryPin {
public:
    explicit DirectoryPin(const std::filesystem::path &path) : path_(checkedPath(path)) {
        try {
#ifdef _WIN32
        state::windows_detail::LocalPath parts;
        try { parts = state::windows_detail::localPath(path.native()); } catch (...) { unsafe(); }
        if (GetDriveTypeW(parts.drive.c_str()) != DRIVE_FIXED) unsafe();
        wchar_t volume[64]{};
        if (!GetVolumeNameForVolumeMountPointW(parts.drive.c_str(), volume, 64)) unsafe();
        volume_ = volume;
        native_ = volume;
        open(native_);
        wchar_t filesystem[32]{}; DWORD flags = 0;
        if (!GetVolumeInformationByHandleW(handles_.front(), nullptr, 0, nullptr, nullptr, &flags, filesystem, 32) ||
            std::wstring(filesystem) != L"NTFS" || !(flags & FILE_PERSISTENT_ACLS)) unsafe();
        for (const auto &part : parts.components) {
            if (native_.back() != wchar_t(0x5c)) native_ += wchar_t(0x5c);
            native_ += part;
            open(native_);
        }
#else
        int parent = ::open("/", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
        if (parent < 0) unsafe();
        handles_.push_back(parent);
        for (const auto &part : path.relative_path()) {
            const auto name = part.native();
            if (name.empty() || name == "." || name == ".." || name.size() > 255) unsafe();
            const int fd = ::openat(parent, name.c_str(), O_DIRECTORY | O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            if (fd < 0) unsafe();
            handles_.push_back(fd);
            struct stat value{};
            if (::fstat(fd, &value) != 0) unsafe();
            links_.push_back({parent, name, value});
            parent = fd;
        }
        if (::fstat(handles_.back(), &stamp_) != 0) unsafe();
#endif
        } catch (...) {
            close();
            throw;
        }
    }
    ~DirectoryPin() { close(); }
    DirectoryPin(const DirectoryPin &) = delete;
    DirectoryPin &operator=(const DirectoryPin &) = delete;
    void requireDisjoint(const DirectoryPin &other) const {
        verify(); other.verify();
#ifdef _WIN32
        if (CompareStringOrdinal(volume_.data(), int(volume_.size()), other.volume_.data(),
                                 int(other.volume_.size()), TRUE) != CSTR_EQUAL) unsafe();
        const auto same = [](HANDLE a, HANDLE b) {
            BY_HANDLE_FILE_INFORMATION x{}, y{};
            if (!GetFileInformationByHandle(a, &x) || !GetFileInformationByHandle(b, &y)) unsafe();
            return x.dwVolumeSerialNumber == y.dwVolumeSerialNumber &&
                x.nFileIndexHigh == y.nFileIndexHigh && x.nFileIndexLow == y.nFileIndexLow;
        };
#else
        const auto same = [](int a, int b) {
            struct stat x{}, y{};
            if (::fstat(a, &x) != 0 || ::fstat(b, &y) != 0) unsafe();
            return x.st_dev == y.st_dev && x.st_ino == y.st_ino;
        };
#endif
        for (const auto handle : handles_) if (same(handle, other.handles_.back())) unsafe();
        for (const auto handle : other.handles_) if (same(handle, handles_.back())) unsafe();
    }
    void close() noexcept {
        for (const auto handle : handles_) {
#ifdef _WIN32
            CloseHandle(handle);
#else
            ::close(handle);
#endif
        }
        handles_.clear();
    }
    void create(const std::string &name, bool acceptExisting) const {
        verify();
        if (name.empty() || name.size() > 100 || std::any_of(name.begin(), name.end(),
            [](unsigned char c) { return !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'); })) unsafe();
#ifdef _WIN32
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) unsafe();
        struct Close { HANDLE handle; ~Close() { CloseHandle(handle); } } close{token};
        DWORD size = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &size);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !size || size > 65536) unsafe();
        Bytes user(size);
        if (!GetTokenInformation(token, TokenUser, user.data(), size, &size)) unsafe();
        const auto sid = reinterpret_cast<const TOKEN_USER *>(user.data())->User.Sid;
        LPWSTR sidText = nullptr;
        if (!ConvertSidToStringSidW(sid, &sidText)) unsafe();
        struct Free { void *p; ~Free() { if (p) LocalFree(p); } } freeSid{sidText};
        const std::wstring rules = L"O:" + std::wstring(sidText) + L"D:P(A;OICI;FA;;;" + sidText +
                                   L")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(rules.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) unsafe();
        Free freeDescriptor{descriptor};
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
        const auto child = native_ + wchar_t(0x5c) + std::wstring(name.begin(), name.end());
        if (!CreateDirectoryW(child.c_str(), &attributes) &&
            !(acceptExisting && GetLastError() == ERROR_ALREADY_EXISTS)) unsafe();
#else
        if (::mkdirat(handles_.back(), name.c_str(), 0700) != 0 && !(acceptExisting && errno == EEXIST)) unsafe();
        const int child = ::openat(handles_.back(), name.c_str(), O_DIRECTORY | O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (child < 0) unsafe();
        struct Close { int handle; ~Close() { ::close(handle); } } close{child};
        struct stat value{}, mapped{};
        if (::fstat(child, &value) != 0 || ::fstatat(handles_.back(), name.c_str(), &mapped, AT_SYMLINK_NOFOLLOW) != 0 ||
            value.st_dev != stamp_.st_dev || value.st_ino != mapped.st_ino || !S_ISDIR(value.st_mode)) unsafe();
        if (::fsync(child) != 0 || ::fsync(handles_.back()) != 0) unsafe();
#endif
        const DirectoryPin verify(path_ / name);
        (void)verify;
        this->verify();
    }
private:
    std::filesystem::path path_;
#ifdef _WIN32
    std::vector<HANDLE> handles_;
    std::wstring native_, volume_;
    DWORD volumeSerial_ = 0;
    void open(const std::wstring &path) {
        const auto handle = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (handle == INVALID_HANDLE_VALUE) unsafe();
        handles_.push_back(handle);
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(handle, &info) || !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_DEVICE))) unsafe();
        if (!volumeSerial_) volumeSerial_ = info.dwVolumeSerialNumber;
        if (info.dwVolumeSerialNumber != volumeSerial_) unsafe();
    }
#else
    struct Link { int parent; std::string name; struct stat stamp; };
    std::vector<int> handles_;
    std::vector<Link> links_;
    struct stat stamp_{};
#endif
    void verify() const {
#ifndef _WIN32
        for (std::size_t i = 0; i < links_.size(); ++i) {
            const auto &link = links_[i];
            struct stat named{}, pinned{};
            if (::fstatat(link.parent, link.name.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0 ||
                ::fstat(handles_[i + 1], &pinned) != 0 || named.st_dev != link.stamp.st_dev ||
                named.st_ino != link.stamp.st_ino || named.st_mode != link.stamp.st_mode ||
                named.st_uid != link.stamp.st_uid || named.st_gid != link.stamp.st_gid ||
                pinned.st_dev != named.st_dev || pinned.st_ino != named.st_ino) unsafe();
        }
#endif
    }
};

struct Manifest {
    SignedSetupRole role = SignedSetupRole::Applicant;
    bool ready = false;
    Genesis genesis;
    Member local;
    std::filesystem::path transport;
    Bytes vault, journal, checkpoint, groupKey, identity;
    std::uint64_t created = 0;
    ~Manifest() {
        for (auto *bytes : {&vault, &journal, &checkpoint, &groupKey, &identity}) crypto::wipe(*bytes);
    }
    Manifest() = default;
    Manifest(Manifest &&) = default;
    Manifest &operator=(Manifest &&) = delete;
    Manifest(const Manifest &) = delete;
};
Bytes encode(const Manifest &m) {
    Bytes bytes{1, std::uint8_t(m.role == SignedSetupRole::Founder), std::uint8_t(m.ready)};
    append(bytes, publicGenesis(m.genesis));
    for (const auto *field : {&m.local.id, &m.local.signingKey, &m.local.encryptionKey}) append(bytes, *field);
    const auto path = m.transport.generic_u8string();
    blob(bytes, Bytes(path.begin(), path.end()));
    for (const auto *field : {&m.vault, &m.journal, &m.checkpoint, &m.groupKey, &m.identity}) blob(bytes, *field);
    number(bytes, m.created);
    return bytes;
}
class Reader {
public:
    explicit Reader(const Bytes &bytes) : bytes_(bytes) {}
    unsigned byte() { if (pos_ == bytes_.size()) refuse(); return bytes_[pos_++]; }
    std::uint64_t number() { std::uint64_t n = 0; for (int i = 0; i < 8; ++i) n = (n << 8) | byte(); return n; }
    Token token() { Token t{}; for (auto &value : t) value = std::uint8_t(byte()); return t; }
    Bytes blob(std::size_t maximum) {
        const auto count = number();
        if (count > maximum || count > bytes_.size() - pos_) refuse();
        Bytes result(bytes_.begin() + pos_, bytes_.begin() + pos_ + std::size_t(count));
        pos_ += std::size_t(count);
        return result;
    }
    bool end() const { return pos_ == bytes_.size(); }
private:
    const Bytes &bytes_; std::size_t pos_ = 0;
};
Manifest decode(const Bytes &bytes) {
    if (bytes.size() > 8192) refuse();
    Reader r(bytes);
    if (r.byte() != 1) refuse();
    const auto founder = r.byte(), ready = r.byte();
    if (founder > 1 || ready > 1) refuse();
    Manifest m;
    m.role = founder ? SignedSetupRole::Founder : SignedSetupRole::Applicant;
    m.ready = ready != 0;
    m.genesis = {r.token(), {r.token(), r.token(), r.token()}, r.token(), r.token()};
    m.local = {r.token(), r.token(), r.token()};
    const Wiped path{r.blob(4096)};
    m.transport = checkedPath(std::filesystem::u8path(std::string(path.bytes.begin(), path.bytes.end())));
    m.vault = r.blob(32); m.journal = r.blob(32); m.checkpoint = r.blob(32);
    m.groupKey = r.blob(32); m.identity = r.blob(256); m.created = r.number();
    if (!r.end() || !m.created || !SodiumVerifier::validMember(m.local) || m.vault.size() != 32 ||
        m.journal.size() != 32 || m.checkpoint.size() != 32 || m.vault == m.journal ||
        m.vault == m.checkpoint || m.journal == m.checkpoint ||
        ((m.role == SignedSetupRole::Founder) != (m.local == m.genesis.founder)) ||
        (m.role == SignedSetupRole::Founder ? m.groupKey.size() != 32 : !m.groupKey.empty()) ||
        (m.ready ? !m.identity.empty() : m.identity.empty())) refuse();
    const Wiped canonical{encode(m)};
    if (canonical.bytes != bytes) refuse();
    for (const auto *credential : {&m.vault, &m.journal, &m.checkpoint})
        if (std::all_of(credential->begin(), credential->end(), [](auto value) { return value == 0; }) ||
            (!m.groupKey.empty() && *credential == m.groupKey)) refuse();
    return m;
}
transaction::Record initial(const std::string &binding, const Manifest &m) {
    transaction::Record r;
    r.schema = 2; r.binding = binding; r.keyIdentity = binding.substr(13);
    r.local = transaction::Snapshot{{{Mime, encode(m)}}};
    return r;
}
Manifest manifest(const transaction::Record &record, const std::string &binding) {
    if (record.schema != 2 || record.binding != binding || record.keyIdentity != binding.substr(13) || record.head ||
        record.pending || !record.local || record.local->size() != 1 || record.local->front().size() != 1 ||
        record.allocatedSequence || record.publication || record.resolution || !record.archives.empty() ||
        record.preserved || !record.witnessed.empty()) refuse();
    const auto &entry = *record.local->front().begin();
    if (entry.first != Mime) refuse();
    auto m = decode(entry.second);
    if (record.generation != (m.ready ? 1u : 0u)) refuse();
    return m;
}
SignedSetupPaths makePaths(const std::filesystem::path &root, const std::filesystem::path &transport) {
    return {root, root / "identity", root / "journal", root / "checkpoint", root / "staging", transport};
}
void provisionTransport(const Manifest &m) {
    if (m.role == SignedSetupRole::Founder && !m.ready) {
        DirectoryPin transport(m.transport);
        transport.create("events", true);
        transport.create("control", true);
        const Membership membership(m.genesis.group, m.genesis.founder, m.genesis.recovery, m.genesis.initialKeyCommitment);
        transport.create(storage::signedEventFolderName({m.genesis.group, membership.current().root, 0}), true);
    }
    const storage::Directory transport(m.transport);
    const Membership membership(m.genesis.group, m.genesis.founder, m.genesis.recovery, m.genesis.initialKeyCommitment);
    (void)transport.openSignedEvents({m.genesis.group, membership.current().root, 0});
    const DirectoryPin control(m.transport / "control");
    (void)control;
}
std::unique_ptr<Identity> provision(const SignedSetupPaths &p, Manifest &m, std::uint64_t now) {
    if (now < m.created || overlaps(p.root, p.transport)) unsafe();
    const DirectoryPin root(p.root), shared(p.transport);
    root.requireDisjoint(shared);
    if (!m.ready) for (const auto *name : {"identity", "journal", "checkpoint", "staging"}) root.create(name, true);
    for (const auto &directory : {p.identity, p.journal, p.checkpoint, p.staging}) {
        state::FileStore check(directory, "signed-setup-directory", Bytes(32));
        (void)check;
    }
    const Membership membership(m.genesis.group, m.genesis.founder, m.genesis.recovery, m.genesis.initialKeyCommitment);
    const IdentityVaultPins pins{m.genesis.group, membership.current().root, m.local};
    std::unique_ptr<Identity> identity;
    try { identity = IdentityVault::load(p.identity, pins, m.vault); }
    catch (const state::Error &e) {
        if (m.ready || e.code() != state::ErrorCode::Missing) throw;
        identity = Identity::restore(m.identity);
        if (identity->member() != m.local) refuse();
        IdentityVault::initialize(p.identity, pins, m.vault, *identity);
        identity = IdentityVault::load(p.identity, pins, m.vault);
    }
    if (!m.ready) {
        const Wiped existing{identity->exportPrivate()};
        if (existing.bytes != m.identity) refuse();
    }
    state::FileStore journal(p.journal, TrustJournal::binding(m.genesis, m.local), m.journal);
    try {
        TrustJournal verify(journal, m.genesis, m.local);
        (void)verify.inspect();
    } catch (const state::Error &e) {
        if (m.ready || e.code() != state::ErrorCode::Missing) throw;
        TrustJournal::initialize(journal, m.genesis, m.local, m.created);
        TrustJournal verify(journal, m.genesis, m.local);
        (void)verify.inspect();
    }
    provisionTransport(m);
#ifdef _WIN32
    storage::Directory(p.transport).checkPublicationStaging(p.staging);
#endif
    if (!m.ready && m.role == SignedSetupRole::Founder) {
        auto key = SyncKey::import(m.groupKey);
        if (key->commitment(m.genesis.group, 0) != m.genesis.initialKeyCommitment) refuse();
        TrustJournal founder(journal, m.genesis, m.local, key.get());
        const auto state = founder.inspect();
        if (state.forked || state.state.epoch || state.state.keyGeneration ||
            state.state.members != std::vector<Member>{m.local}) refuse();
        const storage::Directory transport(p.transport);
#ifdef _WIN32
        const auto staging = p.staging;
#else
        const std::filesystem::path staging;
#endif
        transport.checkPublicationStaging(staging);
        if (state.pendingEvent) {
            if (!state.pendingEvent->ready) {
                // Provisioning has never exposed this identity to a caller,
                // so this exact empty burned slot belongs to the empty Seed.
                founder.discardClipboardEvent(state.pendingEvent->sequence, now);
            } else {
                auto prepared = founder.resumeClipboardEvent(state.pendingEvent->sequence, now);
                const SignedEventContext context{state.state.group, state.state.root, state.state.digest,
                    state.state.keyCommitment, m.local.id, 0};
                const auto id = history::makeId(SignedEventCodec::deviceName(m.local.id), prepared.sequence);
                const auto event = SignedEventCodec::open(
                    {id, {reinterpret_cast<const char *>(prepared.wire.data()), prepared.wire.size()}}, context, m.local, *key);
                if (!event.revision.parents.empty() || !event.items.empty()) refuse();
                (void)founder.publishClipboardEvent(prepared.sequence, *key, transport, now, ClipboardPublication::Seed, staging);
            }
        }
        const auto history = founder.scanClipboardEvents(*key, transport, now);
        if (history.events.empty()) {
            const auto prepared = founder.prepareClipboardEvent(*identity, *key, {}, {}, now);
            (void)founder.publishClipboardEvent(prepared.sequence, *key, transport, now, ClipboardPublication::Seed, staging);
        } else if (history.events.size() != 1 || history.graph.tips().size() != 1 ||
                   !history.events.front().revision.parents.empty() || !history.events.front().items.empty() ||
                   history.events.front().revision.device != SignedEventCodec::deviceName(m.local.id)) {
            refuse();
        }
        const auto verified = founder.scanClipboardEvents(*key, transport, now);
        if (verified.events.size() != 1 || verified.graph.tips().size() != 1 || !verified.events.front().items.empty()) refuse();
    }
    return identity;
}
void requirePassword(const Bytes &password) {
    state::validateSecret(password, state::Protection::Password);
    if (password.size() < 12) throw state::Error(state::ErrorCode::InvalidKey, "Signed setup password needs at least 12 UTF-8 bytes");
}
bool sameRecord(const transaction::Record &a, const transaction::Record &b) {
    const Wiped first{state::serialize(a)}, second{state::serialize(b)};
    return first.bytes == second.bytes;
}
} // namespace

struct SignedSetup::Impl {
    SignedSetupRole role;
    Genesis genesis;
    Member local;
    SignedSetupPaths paths;
    std::unique_ptr<Identity> identity;
    std::unique_ptr<SyncKey> journal, checkpoint, founder;
};

std::filesystem::path SignedSetup::createPrivateRoot(const std::filesystem::path &parent) {
    DirectoryPin directory(parent);
    const auto name = "copyq-signed-" + hex(crypto::random(8));
    directory.create(name, false);
    const auto root = parent / name;
    state::FileStore validate(root, "signed-setup-directory", Bytes(32));
    return root;
}

std::string SignedSetup::invitation(const Genesis &genesis) { return InvitePrefix + hex(publicGenesis(genesis)); }
Genesis SignedSetup::parseInvitation(const std::string &invitation) {
    const auto prefix = std::string(InvitePrefix);
    if (invitation.compare(0, prefix.size(), prefix) != 0) refuse();
    const auto bytes = unhex(invitation.substr(prefix.size()));
    Reader r(bytes);
    Genesis genesis{r.token(), {r.token(), r.token(), r.token()}, r.token(), r.token()};
    (void)publicGenesis(genesis);
    return genesis;
}
Token SignedSetup::fingerprint(const Genesis &genesis) {
    Bytes input{'C','q','s','S','i','g','n','e','d','G','r','o','u','p',0};
    append(input, publicGenesis(genesis));
    const auto hash = crypto::sha256(input);
    Token result{};
    std::copy(hash.begin(), hash.end(), result.begin());
    return result;
}

namespace {
void createSetup(const std::filesystem::path &root, const Bytes &password,
    const std::filesystem::path &transport, const Genesis *trustedGenesis, const Token *confirmation,
    std::uint64_t now, const SignedSetup::PathValidator &validatePaths) {
    requirePassword(password);
    const auto privateRoot = checkedPath(root), shared = checkedPath(transport);
    if (!now || overlaps(privateRoot, shared)) unsafe();
    const DirectoryPin pinnedRoot(privateRoot), pinnedTransport(shared);
    pinnedRoot.requireDisjoint(pinnedTransport);
    if (validatePaths && !validatePaths(privateRoot, shared)) unsafe();
    if (trustedGenesis && (!confirmation || SignedSetup::fingerprint(*trustedGenesis) != *confirmation))
        throw JournalError(JournalCode::Confirmation);
    state::FileStore session(privateRoot, setupBinding(privateRoot), Bytes(32), {},
                             state::Protection::Key, state::LeaseKind::Session);
    const auto owner = session.lock();
    if (!owner) throw state::Error(state::ErrorCode::Busy, "Signed setup is already open");
    state::FileStore setup(privateRoot, setupBinding(privateRoot), password, {}, state::Protection::Password);
    const auto lease = setup.lock();
    if (!lease) throw state::Error(state::ErrorCode::Busy, "Signed setup is already open");
    setup.checkInitializable();
    for (const auto &entry : std::filesystem::directory_iterator(privateRoot))
        if (entry.path().filename() != state::FileStore::LockName &&
            entry.path().filename() != state::FileStore::SessionLockName) unsafe();
    if (!trustedGenesis && !std::filesystem::is_empty(shared)) unsafe();
    Manifest m;
    m.role = trustedGenesis ? SignedSetupRole::Applicant : SignedSetupRole::Founder;
    auto identity = Identity::generate();
    m.local = identity->member();
    m.transport = shared; m.created = now;
    m.vault = crypto::random(32); m.journal = crypto::random(32); m.checkpoint = crypto::random(32);
    if (trustedGenesis) {
        m.genesis = *trustedGenesis;
    } else {
        auto key = SyncKey::generate();
        m.groupKey = key->exportPrivate();
        const auto group = randomToken();
        m.genesis = {group, m.local, randomToken(), key->commitment(group, 0)};
    }
    m.identity = identity->exportPrivate();
    const PrivateRecord record{initial(setupBinding(privateRoot), m)};
    (void)decode(record.value.local->front().begin()->second);
    setup.initialize(record.value);
    const PrivateRecord readback{setup.load()};
    if (!sameRecord(readback.value, record.value))
        throw state::Error(state::ErrorCode::CommitUnconfirmed, "Signed setup readback is unconfirmed");
    // Reopen through the same authenticated path after releasing both leases.
}
} // namespace

std::unique_ptr<SignedSetup> SignedSetup::createFounder(const std::filesystem::path &root, const Bytes &password,
    const std::filesystem::path &transport, std::uint64_t now, const PathValidator &validatePaths) {
    createSetup(root, password, transport, nullptr, nullptr, now, validatePaths);
    return open(root, password, now, validatePaths);
}
std::unique_ptr<SignedSetup> SignedSetup::createApplicant(const std::filesystem::path &root, const Bytes &password,
    const std::filesystem::path &transport, const Genesis &genesis, const Token &confirmed, std::uint64_t now,
    const PathValidator &validatePaths) {
    createSetup(root, password, transport, &genesis, &confirmed, now, validatePaths);
    return open(root, password, now, validatePaths);
}

std::unique_ptr<SignedSetup> SignedSetup::open(const std::filesystem::path &root, const Bytes &password, std::uint64_t now,
    const PathValidator &validatePaths) {
    requirePassword(password);
    const auto privateRoot = checkedPath(root);
    const auto binding = setupBinding(privateRoot);
    state::FileStore session(privateRoot, binding, Bytes(32), {}, state::Protection::Key, state::LeaseKind::Session);
    const auto owner = session.lock();
    if (!owner) throw state::Error(state::ErrorCode::Busy, "Signed setup is already open");
    state::FileStore setup(privateRoot, binding, password, {}, state::Protection::Password);
    const auto lease = setup.lock();
    if (!lease) throw state::Error(state::ErrorCode::Busy, "Signed setup is already open");
    PrivateRecord record{setup.load()};
    auto m = manifest(record.value, binding);
    const auto p = makePaths(privateRoot, m.transport);
    if (validatePaths && !validatePaths(p.root, p.transport)) unsafe();
    auto identity = provision(p, m, now);
    if (!m.ready) {
        m.ready = true;
        crypto::wipe(m.identity);
        PrivateRecord ready{initial(binding, m)};
        ready.value.generation = 1;
        setup.commit(record.value, ready.value);
        const PrivateRecord readback{setup.load()};
        if (!sameRecord(readback.value, ready.value))
            throw state::Error(state::ErrorCode::CommitUnconfirmed, "Signed setup readback is unconfirmed");
    }
    auto impl = std::make_unique<Impl>();
    impl->role = m.role; impl->genesis = m.genesis; impl->local = m.local; impl->paths = p;
    impl->identity = std::move(identity);
    impl->journal = SyncKey::import(m.journal);
    impl->checkpoint = SyncKey::import(m.checkpoint);
    if (!m.groupKey.empty()) {
        impl->founder = SyncKey::import(m.groupKey);
        if (impl->founder->commitment(m.genesis.group, 0) != m.genesis.initialKeyCommitment) refuse();
    }
    return std::unique_ptr<SignedSetup>(new SignedSetup(std::move(impl)));
}

Bytes SignedSetup::unlockCheckpoint(const std::filesystem::path &root, const Bytes &password,
    const JoinActivation &expected) {
    requirePassword(password);
    const auto privateRoot = checkedPath(root);
    const DirectoryPin pinned(privateRoot);
    (void)pinned;
    // Existing ready setups already have this lock. Refuse a missing leaf
    // rather than creating synchronization state during a local tab unlock.
    const auto lockStatus = std::filesystem::symlink_status(privateRoot / state::FileStore::LockName);
    if (!std::filesystem::is_regular_file(lockStatus)) unsafe();
    const auto binding = setupBinding(privateRoot);
    state::FileStore setup(privateRoot, binding, password, {}, state::Protection::Password);
    const auto lease = setup.lock();
    if (!lease) throw state::Error(state::ErrorCode::Busy, "Signed setup is being updated");
    const PrivateRecord record{setup.load()};
    const auto m = manifest(record.value, binding);
    const Membership membership(m.genesis.group, m.genesis.founder, m.genesis.recovery, m.genesis.initialKeyCommitment);
    state::validateBinding(expected.profileBinding);
    if (!m.ready || expected.group != m.genesis.group || expected.root != membership.current().root ||
        expected.member != m.local.id || expected.head == Token{} || expected.tipDigest == Token{} ||
        !storage::validSignedEventId(expected.tipId)) refuse();
    return m.checkpoint;
}

SignedSetup::SignedSetup(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
SignedSetup::~SignedSetup() = default;
SignedSetupRole SignedSetup::role() const noexcept { return impl_->role; }
const Genesis &SignedSetup::genesis() const noexcept { return impl_->genesis; }
const Member &SignedSetup::member() const noexcept { return impl_->local; }
const SignedSetupPaths &SignedSetup::paths() const noexcept { return impl_->paths; }
Identity &SignedSetup::identity() const noexcept { return *impl_->identity; }
const SyncKey *SignedSetup::founderKey() const noexcept { return impl_->founder.get(); }
Bytes SignedSetup::journalCredential() const { return impl_->journal->exportPrivate(); }
Bytes SignedSetup::checkpointCredential() const { return impl_->checkpoint->exportPrivate(); }
} // namespace cqs::trust
