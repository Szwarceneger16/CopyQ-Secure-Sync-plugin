// SPDX-License-Identifier: GPL-3.0-or-later
#include "crypto.h"
#include "test_check.h"
#include <iostream>
#include <string>
using cqs::crypto::Bytes;
static Bytes hex(const std::string &s) {
    auto value=[](char c)->unsigned {return c<='9'?static_cast<unsigned>(c-'0'):static_cast<unsigned>(c-'a'+10);};
    CHECK(s.size()%2==0);
    Bytes out;for(std::size_t i=0;i<s.size();i+=2)out.push_back(static_cast<std::uint8_t>((value(s[i])<<4)|value(s[i+1])));
    return out;
}
int main(){
    const auto key=hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto nonce=hex("000102030405060708090a0b");
    const auto aad=hex("436f7079512d5365637572652d53796e632d6576656e742d7631007b22646576696365223a226d696e742d6c6162222c22706172656e7473223a5b5d2c2270726f746f636f6c223a22636f7079712d7365637572652d73796e632d7631222c22736571223a317d");
    const auto body=hex("7b226974656d73223a5b2255316c4f5131395552564e55587a41774d513d3d225d2c22746162223a2273796e6365645f74726179222c2276223a317d");
    const auto expected=hex("3f9e7d4d0fc98bd6a0172501e7e34da172d9b380fc76558f33ea4df7319e0d06b4452429feeb5bd426162dc7264b6376a3d04fa4107af7086ebd79ab2a4ff0eeb41dd49459ab3019df3a396bcf9dfa53614097f6");
    auto compressed=cqs::crypto::zlibCompress(body);
    CHECK(cqs::crypto::aes256GcmEncrypt(key,nonce,compressed,aad)==expected);
    auto restored=cqs::crypto::zlibDecompressBounded(cqs::crypto::aes256GcmDecrypt(key,nonce,expected,aad),1024);
    CHECK(restored==body);
    // AAD is cryptographically authenticated.
    auto wrong=aad;wrong.back()^=1;bool rejected=false;
    try{(void)cqs::crypto::aes256GcmDecrypt(key,nonce,expected,wrong);}catch(const cqs::crypto::Error&){rejected=true;}
    CHECK(rejected);
    std::cout << "PASS C++/Python cryptography v0.1.1 protocol interoperability\n";
}
