// SPDX-License-Identifier: GPL-3.0-or-later
#include "state_record.h"
#include "test_check.h"
#include <algorithm>
#include <functional>
#include <iostream>
using cqs::crypto::Bytes;
namespace {
void refused(const std::function<void()> &f) { bool rejected=false; try { f(); } catch(const std::exception &) { rejected=true; } CHECK(rejected); }
Bytes bytes(const char *s) { return {s, s + std::char_traits<char>::length(s)}; }
}
int main() {
    namespace st=cqs::state;
    const Bytes password=bytes("public-fixture-password");
    const Bytes salt(16, 0x42);
    const auto derived=cqs::crypto::passwordKey(password,salt,st::PasswordIterations);
    const Bytes expected={0xcf,0x9b,0x46,0x73,0xe6,0xf8,0x72,0xa4,0xd7,0x7b,0xe9,0xab,0xea,0x39,0xc1,0x0d,0x2a,0x73,0x29,0x69,0xb8,0x7f,0x43,0xf8,0xff,0x41,0xc7,0xe1,0xd1,0x40,0xd1,0x4a};
    CHECK(derived==expected);
    const cqs::transaction::Record r{1,"PublicVaultFixtureV1",0,{},{}};
    const auto seal=[&]{return st::seal(password,r.binding,r,{},st::Protection::Password);};
    const auto wire=seal(); CHECK(wire!=seal());
    CHECK(st::serialize(st::unseal(password,r.binding,wire,{},st::Protection::Password))==st::serialize(r));
    refused([&]{st::unseal(bytes("wrong-password"),r.binding,wire,{},st::Protection::Password);});
    refused([&]{st::unseal(password,"DifferentBinding",wire,{},st::Protection::Password);});
    refused([&]{st::unseal(Bytes(32,1),r.binding,wire);});
    for(auto offset:{0U,8U,24U,28U,unsigned(wire.size()-1)}) {
        auto bad=wire; bad[offset]^=1;
        refused([&]{st::unseal(password,r.binding,bad,{},st::Protection::Password);});
    }
    refused([&]{cqs::crypto::passwordKey({},salt,600000);});
    refused([&]{cqs::crypto::passwordKey(Bytes(1025,1),salt,600000);});
    refused([&]{cqs::crypto::passwordKey(password,Bytes(15),600000);});
    refused([&]{cqs::crypto::passwordKey(password,salt,1000001);});
    auto tiny=st::Limits{}; tiny.recordBytes=1;
    refused([&]{st::unseal(password,r.binding,wire,tiny,st::Protection::Password);});
    std::cout<<"Password vault KDF vector, AEAD, parameter/binding/type/resource checks passed\n";
}
