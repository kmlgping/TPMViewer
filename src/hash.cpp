// hash.cpp — SHA1/256/384/512 one-shot hashes backed by Windows CNG (bcrypt.h).
#include "hash.hpp"

#include <cstdio>
#include <string>

#include <windows.h>
#include <bcrypt.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

namespace tcg {

namespace {

LPCWSTR CngName(uint16_t alg) {
    switch (alg) {
        case AlgSha1:   return BCRYPT_SHA1_ALGORITHM;
        case AlgSha256: return BCRYPT_SHA256_ALGORITHM;
        case AlgSha384: return BCRYPT_SHA384_ALGORITHM;
        case AlgSha512: return BCRYPT_SHA512_ALGORITHM;
    }
    return nullptr;
}

std::vector<uint8_t> CngHash(LPCWSTR name, const uint8_t* data, size_t len) {
    std::vector<uint8_t> out;
    if (!name || (len && !data)) return out;
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, name, nullptr, 0) != STATUS_SUCCESS) return out;
    DWORD objLen = 0, cb = 0;
    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objLen),
                      sizeof(objLen), &cb, 0);
    std::vector<uint8_t> obj(objLen);
    BCRYPT_HASH_HANDLE h = nullptr;
    if (BCryptCreateHash(alg, &h, obj.data(), objLen, nullptr, 0, 0) == STATUS_SUCCESS) {
        if (len > 0)
            BCryptHashData(h, const_cast<PUCHAR>(data), static_cast<ULONG>(len), 0);
        DWORD hashLen = 0;
        BCryptGetProperty(h, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLen),
                          sizeof(hashLen), &cb, 0);
        out.resize(hashLen);
        BCryptFinishHash(h, out.data(), hashLen, 0);
        BCryptDestroyHash(h);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return out;
}

} // namespace

std::vector<uint8_t> Sha1(const uint8_t* data, size_t len)   { return CngHash(BCRYPT_SHA1_ALGORITHM, data, len); }
std::vector<uint8_t> Sha256(const uint8_t* data, size_t len) { return CngHash(BCRYPT_SHA256_ALGORITHM, data, len); }
std::vector<uint8_t> Sha384(const uint8_t* data, size_t len) { return CngHash(BCRYPT_SHA384_ALGORITHM, data, len); }
std::vector<uint8_t> Sha512(const uint8_t* data, size_t len) { return CngHash(BCRYPT_SHA512_ALGORITHM, data, len); }

std::vector<uint8_t> HashByAlg(uint16_t alg, const uint8_t* data, size_t len) {
    LPCWSTR name = CngName(alg);
    if (!name) return {};
    return CngHash(name, data, len);
}

size_t HashSizeByAlg(uint16_t alg) {
    switch (alg) {
        case AlgSha1:   return 20;
        case AlgSha256: return 32;
        case AlgSha384: return 48;
        case AlgSha512: return 64;
        case AlgSm3:    return 32; // parseable in logs, not hashable via CNG
    }
    return 0;
}

std::string AlgName(uint16_t alg) {
    switch (alg) {
        case AlgSha1:   return "SHA1";
        case AlgSha256: return "SHA256";
        case AlgSha384: return "SHA384";
        case AlgSha512: return "SHA512";
        case AlgSm3:    return "SM3_256";
    }
    char buf[16];
    snprintf(buf, sizeof(buf), "ALG_0x%04X", alg);
    return buf;
}

} // namespace tcg
