// SPDX-License-Identifier: GPL-3.0-or-later
// Windows CNG: same AES-256-GCM wire format as OpenSSL/Python; no crypto DLL to deploy.
#include "crypto.h"
#include <windows.h>
#include <bcrypt.h>
#include <limits>
#include <algorithm>
namespace cqs::crypto {
namespace {
ULONG checkedSize(std::size_t n) {
    if (n > std::numeric_limits<ULONG>::max()) throw Error("Cryptographic input exceeds CNG bounds");
    return static_cast<ULONG>(n);
}
void check(NTSTATUS status) { if (status < 0) throw Error("Windows CNG operation failed"); }
struct Algorithm {
    BCRYPT_ALG_HANDLE handle=nullptr;
    Algorithm() {
        check(BCryptOpenAlgorithmProvider(&handle,BCRYPT_AES_ALGORITHM,nullptr,0));
        const auto status=BCryptSetProperty(handle,BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),sizeof(BCRYPT_CHAIN_MODE_GCM),0);
        if(status<0){BCryptCloseAlgorithmProvider(handle,0);handle=nullptr;check(status);}
    }
    ~Algorithm(){if(handle)BCryptCloseAlgorithmProvider(handle,0);}
};
struct Key {
    BCRYPT_KEY_HANDLE handle=nullptr;
    Bytes buffer;
    Key(BCRYPT_ALG_HANDLE algorithm,const Bytes &key) {
        ULONG length=0,written=0;
        check(BCryptGetProperty(algorithm,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&length),sizeof(length),&written,0));
        buffer.resize(length);
        check(BCryptGenerateSymmetricKey(algorithm,&handle,buffer.data(),length,
            const_cast<PUCHAR>(key.data()),checkedSize(key.size()),0));
    }
    ~Key(){if(handle)BCryptDestroyKey(handle);wipe(buffer);}
};
Bytes crypt(bool encrypt,const Bytes &key,const Bytes &nonce,const Bytes &input,const Bytes &aad) {
    if(key.size()!=32 || nonce.size()!=12 || (!encrypt && input.size()<16))
        throw Error("Invalid AES-GCM key, nonce or payload");
    const std::size_t length=encrypt?input.size():input.size()-16;
    Algorithm algorithm; Key symmetric(algorithm.handle,key);
    Bytes output(length+16); // Non-null buffer also for empty plaintext.
    Bytes tag(16);
    if(!encrypt) std::copy(input.end()-16,input.end(),tag.begin());
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce=const_cast<PUCHAR>(nonce.data());info.cbNonce=checkedSize(nonce.size());
    info.pbAuthData=const_cast<PUCHAR>(aad.data());info.cbAuthData=checkedSize(aad.size());
    info.pbTag=tag.data();info.cbTag=16;
    ULONG written=0;
    auto operation=encrypt?BCryptEncrypt:BCryptDecrypt;
    const auto status=operation(symmetric.handle,const_cast<PUCHAR>(input.data()),checkedSize(length),
        &info,nullptr,0,output.data(),checkedSize(output.size()),&written,0);
    if(status<0 || written!=length){wipe(output);wipe(tag);throw Error("AES-GCM authentication/operation failed");}
    output.resize(length);
    if(encrypt)output.insert(output.end(),tag.begin(),tag.end());
    wipe(tag);return output;
}
}
Bytes random(std::size_t n){
    if(!n)throw Error("Invalid random byte count");
    Bytes out(n);check(BCryptGenRandom(nullptr,out.data(),checkedSize(n),BCRYPT_USE_SYSTEM_PREFERRED_RNG));return out;
}
Bytes sha256(const Bytes &input) {
    BCRYPT_ALG_HANDLE raw=nullptr;
    check(BCryptOpenAlgorithmProvider(&raw,BCRYPT_SHA256_ALGORITHM,nullptr,0));
    struct Close { BCRYPT_ALG_HANDLE h; ~Close(){BCryptCloseAlgorithmProvider(h,0);} } algorithm{raw};
    Bytes out(32);
    check(BCryptHash(raw,nullptr,0,const_cast<PUCHAR>(input.data()),checkedSize(input.size()),out.data(),checkedSize(out.size())));
    return out;
}
Bytes passwordKey(const Bytes &password, const Bytes &salt, unsigned iterations) {
    if (password.empty() || password.size() > 1024 || salt.size() != 16 || !iterations || iterations > 1000000)
        throw Error("Invalid password derivation parameters");
    BCRYPT_ALG_HANDLE raw = nullptr;
    check(BCryptOpenAlgorithmProvider(&raw, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG));
    struct Close { BCRYPT_ALG_HANDLE h; ~Close() { BCryptCloseAlgorithmProvider(h, 0); } } algorithm{raw};
    Bytes out(32);
    const auto status = BCryptDeriveKeyPBKDF2(raw, const_cast<PUCHAR>(password.data()), checkedSize(password.size()),
        const_cast<PUCHAR>(salt.data()), checkedSize(salt.size()), iterations, out.data(), checkedSize(out.size()), 0);
    if (status < 0) { wipe(out); check(status); }
    return out;
}
Bytes aes256GcmEncrypt(const Bytes &k,const Bytes &n,const Bytes &p,const Bytes &a){return crypt(true,k,n,p,a);}
Bytes aes256GcmDecrypt(const Bytes &k,const Bytes &n,const Bytes &c,const Bytes &a){return crypt(false,k,n,c,a);}
void wipe(Bytes &bytes) noexcept {if(!bytes.empty())SecureZeroMemory(bytes.data(),bytes.size());bytes.clear();}
}
