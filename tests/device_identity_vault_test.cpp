// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_identity_vault.h"
#include "state_store.h"
#include "test_check.h"

#include <algorithm>
#include <functional>
#include <iostream>
#ifdef __linux__
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <sys/stat.h>
#endif

using namespace cqs::trust;
namespace st = cqs::state;
namespace fs = std::filesystem;
using cqs::crypto::Bytes;

namespace {
int cases = 0;
void test(const char *name, const std::function<void()> &body) {
    body(); ++cases;
    std::cout << "PASS " << name << '\n';
}
void rejects(st::ErrorCode code, const std::function<void()> &body) {
    bool failed = false;
    try { body(); } catch (const st::Error &error) {
        failed = true; CHECK(error.code() == code);
    }
    CHECK(failed);
}
Token token(std::uint8_t value) {
    Token result{}; result.fill(value); return result;
}
IdentityVaultPins pinsFor(const Identity &identity) {
    return {token(0x11), token(0x22), identity.member()};
}

#ifdef __linux__
// Disposable test directory and public test credentials. No test touches an
// installed plugin profile or a real device identity.
struct Temp {
    fs::path directory;
    Temp() {
        char pattern[] = "/tmp/cqs-identity-vault-XXXXXX";
        const auto *path = ::mkdtemp(pattern); CHECK(path);
        directory = path;
    }
    ~Temp() {
        std::error_code error; fs::remove_all(directory, error);
    }
    fs::path record() const { return directory / st::FileStore::RecordName; }
};
const Bytes Key(32, 0x42);
const Bytes Password{'v','a','u','l','t','-','t','e','s','t','-','o','n','l','y'};
const Bytes Message{'p','u','b','l','i','c','-','t','e','s','t'};

struct WipedBytes {
    Bytes value;
    ~WipedBytes() { cqs::crypto::wipe(value); }
};
struct WipedRecord {
    cqs::transaction::Record value;
    ~WipedRecord() {
        if (value.local) for (auto &item : *value.local)
            for (auto &field : item) cqs::crypto::wipe(field.second);
    }
};
Bytes read(const fs::path &path) {
    std::ifstream file(path, std::ios::binary);
    CHECK(file.good());
    return {std::istreambuf_iterator<char>(file), {}};
}
void write(const fs::path &path, const Bytes &encrypted) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    CHECK(file.good());
    file.write(reinterpret_cast<const char *>(encrypted.data()), static_cast<std::streamsize>(encrypted.size()));
    file.close(); CHECK(!file.fail());
    CHECK(::chmod(path.c_str(), 0600) == 0);
}
cqs::transaction::Record record(const Temp &temp, const IdentityVaultPins &pins) {
    st::FileStore store(temp.directory, IdentityVault::binding(pins), Key);
    const auto lease = store.lock(); CHECK(lease);
    return store.load();
}
Bytes &secret(cqs::transaction::Record &record) {
    CHECK(record.local && record.local->size() == 1 && record.local->front().size() == 1);
    return record.local->front().begin()->second;
}
#endif
} // namespace

int main() {
    test("vault binding includes group, root and all three member fields", [] {
        const auto identity = Identity::generate(), other = Identity::generate();
        const auto pins = pinsFor(*identity);
        const auto binding = IdentityVault::binding(pins);
        st::validateBinding(binding);
        CHECK(IdentityVault::binding(pins) == binding);
        auto modified = pins;
        modified.group = token(0x33); CHECK(IdentityVault::binding(modified) != binding);
        modified = pins; modified.root = token(0x44); CHECK(IdentityVault::binding(modified) != binding);
        modified = pins; modified.member.id = other->member().id; CHECK(IdentityVault::binding(modified) != binding);
        modified = pins; modified.member.signingKey = other->member().signingKey; CHECK(IdentityVault::binding(modified) != binding);
        modified = pins; modified.member.encryptionKey = other->member().encryptionKey; CHECK(IdentityVault::binding(modified) != binding);
    });
    test("invalid external pins fail before storage access", [] {
        const auto identity = Identity::generate();
        const auto pins = pinsFor(*identity);
        auto modified = pins; modified.group = {};
        rejects(st::ErrorCode::WrongBinding, [&] { IdentityVault::binding(modified); });
        modified = pins; modified.root = {};
        rejects(st::ErrorCode::WrongBinding, [&] { IdentityVault::binding(modified); });
        modified = pins; modified.member.signingKey = {}; modified.member.signingKey[0] = 1;
        rejects(st::ErrorCode::WrongBinding, [&] { IdentityVault::binding(modified); });
    });
#ifdef __linux__
    test("key protected identity survives reopen and retains private filesystem mode", [] {
        Temp temp;
        auto identity = Identity::generate();
        const auto pins = pinsFor(*identity);
        const auto originalSignature = identity->sign(Message);
        IdentityVault::initialize(temp.directory, pins, Key, *identity);
        identity.reset();
        const auto restored = IdentityVault::load(temp.directory, pins, Key);
        CHECK(restored->member() == pins.member);
        CHECK(restored->sign(Message) == originalSignature);
        CHECK(SodiumVerifier{}.verify(pins.member.signingKey, Message, restored->sign(Message)));
        struct stat info{}; CHECK(::stat(temp.record().c_str(), &info) == 0);
        CHECK((info.st_mode & 0777) == 0600);
    });
    test("password protected identity authenticates its password and protection mode", [] {
        Temp temp;
        const auto identity = Identity::generate(); const auto pins = pinsFor(*identity);
        IdentityVault::initialize(temp.directory, pins, Password, *identity, st::Protection::Password);
        CHECK(IdentityVault::load(temp.directory, pins, Password, st::Protection::Password)->member() == pins.member);
        auto wrong = Password; wrong.back() ^= 1;
        rejects(st::ErrorCode::AuthenticationFailed, [&] {
            IdentityVault::load(temp.directory, pins, wrong, st::Protection::Password);
        });
        rejects(st::ErrorCode::InvalidRecord, [&] { IdentityVault::load(temp.directory, pins, Key); });
    });
    test("create-only setup refuses replacement and mismatched initial identity", [] {
        Temp temp;
        const auto identity = Identity::generate(), other = Identity::generate();
        const auto pins = pinsFor(*identity);
        rejects(st::ErrorCode::WrongBinding, [&] { IdentityVault::initialize(temp.directory, pins, Key, *other); });
        CHECK(!fs::exists(temp.record()));
        IdentityVault::initialize(temp.directory, pins, Key, *identity);
        const auto before = read(temp.record());
        rejects(st::ErrorCode::AlreadyInitialized, [&] { IdentityVault::initialize(temp.directory, pins, Key, *identity); });
        CHECK(read(temp.record()) == before);
    });
    test("missing identity is never initialized by load", [] {
        Temp temp;
        const auto identity = Identity::generate(); const auto pins = pinsFor(*identity);
        rejects(st::ErrorCode::Missing, [&] { IdentityVault::load(temp.directory, pins, Key); });
        CHECK(!fs::exists(temp.record()));
        IdentityVault::initialize(temp.directory, pins, Key, *identity);
        CHECK(fs::remove(temp.record()));
        rejects(st::ErrorCode::Missing, [&] { IdentityVault::load(temp.directory, pins, Key); });
        CHECK(!fs::exists(temp.record()));
    });
    test("zero, wrong-length, and too-short new credentials refuse provisioning", [] {
        Temp temp;
        const auto identity = Identity::generate(); const auto pins = pinsFor(*identity);
        rejects(st::ErrorCode::InvalidKey, [&] { IdentityVault::initialize(temp.directory, pins, Bytes(32), *identity); });
        rejects(st::ErrorCode::InvalidKey, [&] { IdentityVault::initialize(temp.directory, pins, Bytes(31, 1), *identity); });
        rejects(st::ErrorCode::InvalidKey, [&] {
            IdentityVault::initialize(temp.directory, pins, Bytes(11, 1), *identity, st::Protection::Password);
        });
        CHECK(!fs::exists(temp.record()));
    });
    test("wrong key, wrong context, and ciphertext modification fail authentication", [] {
        Temp temp;
        const auto identity = Identity::generate(); const auto pins = pinsFor(*identity);
        IdentityVault::initialize(temp.directory, pins, Key, *identity);
        const auto good = read(temp.record());
        auto wrongKey = Key; wrongKey[0] ^= 1;
        rejects(st::ErrorCode::AuthenticationFailed, [&] { IdentityVault::load(temp.directory, pins, wrongKey); });
        auto wrong = pins; wrong.root = token(0x55);
        rejects(st::ErrorCode::AuthenticationFailed, [&] { IdentityVault::load(temp.directory, wrong, Key); });
        CHECK(read(temp.record()) == good);
        auto modified = good; modified.back() ^= 1; write(temp.record(), modified);
        rejects(st::ErrorCode::AuthenticationFailed, [&] { IdentityVault::load(temp.directory, pins, Key); });
        modified = good; modified.pop_back(); write(temp.record(), modified);
        rejects(st::ErrorCode::AuthenticationFailed, [&] { IdentityVault::load(temp.directory, pins, Key); });
        write(temp.record(), good);
        CHECK(IdentityVault::load(temp.directory, pins, Key)->member() == pins.member);
    });
    test("authentic identity vault files cannot be swapped between groups", [] {
        Temp first, second;
        const auto identity = Identity::generate();
        const auto a = pinsFor(*identity); auto b = a; b.group = token(0x66);
        IdentityVault::initialize(first.directory, a, Key, *identity);
        IdentityVault::initialize(second.directory, b, Key, *identity);
        write(first.record(), read(second.record()));
        rejects(st::ErrorCode::AuthenticationFailed, [&] { IdentityVault::load(first.directory, a, Key); });
    });
    test("authenticated records must match exact schema, generation and pin hash", [] {
        Temp temp;
        const auto identity = Identity::generate(); const auto pins = pinsFor(*identity);
        IdentityVault::initialize(temp.directory, pins, Key, *identity);
        WipedRecord decoded{record(temp, pins)};
        const auto binding = IdentityVault::binding(pins);
        decoded.value.schema = 6;
        write(temp.record(), st::seal(Key, binding, decoded.value));
        rejects(st::ErrorCode::InvalidRecord, [&] { IdentityVault::load(temp.directory, pins, Key); });
        decoded.value.schema = 2;
        decoded.value.generation = 1;
        write(temp.record(), st::seal(Key, binding, decoded.value));
        rejects(st::ErrorCode::InvalidRecord, [&] { IdentityVault::load(temp.directory, pins, Key); });
        decoded.value.generation = 0;
        auto node = decoded.value.local->front().extract(decoded.value.local->front().begin());
        node.key() = "text/plain"; decoded.value.local->front().insert(std::move(node));
        write(temp.record(), st::seal(Key, binding, decoded.value));
        rejects(st::ErrorCode::InvalidRecord, [&] { IdentityVault::load(temp.directory, pins, Key); });
        decoded.value.keyIdentity.assign(64, '0');
        write(temp.record(), st::seal(Key, binding, decoded.value));
        rejects(st::ErrorCode::WrongBinding, [&] { IdentityVault::load(temp.directory, pins, Key); });
    });
    test("authenticated payload substitution checks derived ID and both public keys", [] {
        Temp temp;
        const auto identity = Identity::generate(), other = Identity::generate();
        const auto pins = pinsFor(*identity);
        IdentityVault::initialize(temp.directory, pins, Key, *identity);
        WipedRecord decoded{record(temp, pins)};
        WipedBytes original{identity->exportPrivate()}, foreign{other->exportPrivate()};
        auto &payload = secret(decoded.value);
        CHECK(payload.size() == original.value.size() && payload.size() == foreign.value.size());
        CHECK(payload.size() >= 96);
        // The final fields are id, signing seed and independent X25519 scalar.
        const auto offset = static_cast<std::ptrdiff_t>(payload.size() - 96);
        for (std::ptrdiff_t field = 0; field < 3; ++field) {
            std::copy(original.value.begin(), original.value.end(), payload.begin());
            std::copy_n(foreign.value.begin() + offset + field * 32, 32, payload.begin() + offset + field * 32);
            write(temp.record(), st::seal(Key, IdentityVault::binding(pins), decoded.value));
            rejects(st::ErrorCode::WrongBinding, [&] { IdentityVault::load(temp.directory, pins, Key); });
        }
    });
    test("disk contains encrypted envelope and no private identity fields", [] {
        Temp temp;
        const auto identity = Identity::generate(); const auto pins = pinsFor(*identity);
        WipedBytes privateRecord{identity->exportPrivate()};
        IdentityVault::initialize(temp.directory, pins, Key, *identity);
        const auto wire = read(temp.record());
        const Bytes magic{'C','Q','S','R','E','C','0','1'};
        CHECK(wire.size() > magic.size()); CHECK(std::equal(magic.begin(), magic.end(), wire.begin()));
        CHECK(privateRecord.value.size() >= 64);
        CHECK(std::search(wire.begin(), wire.end(), privateRecord.value.end() - 64,
                          privateRecord.value.end() - 32) == wire.end());
        CHECK(std::search(wire.begin(), wire.end(), privateRecord.value.end() - 32,
                          privateRecord.value.end()) == wire.end());
    });
#endif
    std::cout << cases << " device identity vault test cases passed\n";
}
