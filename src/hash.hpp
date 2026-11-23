// hash.hpp — one-shot SHA hashes via CNG (bcrypt.h), keyed by TCG algorithm id.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace tcg {

// TCG algorithm registry ids (as used in TCG_EFI_SPEC_ID_EVENT and Event2 digests).
constexpr uint16_t AlgSha1   = 0x0004;
constexpr uint16_t AlgSha256 = 0x000B;
constexpr uint16_t AlgSha384 = 0x000C;
constexpr uint16_t AlgSha512 = 0x000D;
constexpr uint16_t AlgSm3    = 0x0012;

std::vector<uint8_t> Sha1(const uint8_t* data, size_t len);
std::vector<uint8_t> Sha256(const uint8_t* data, size_t len);
std::vector<uint8_t> Sha384(const uint8_t* data, size_t len);
std::vector<uint8_t> Sha512(const uint8_t* data, size_t len);

inline std::vector<uint8_t> Sha1(const std::vector<uint8_t>& v) { return Sha1(v.data(), v.size()); }
inline std::vector<uint8_t> Sha256(const std::vector<uint8_t>& v) { return Sha256(v.data(), v.size()); }
inline std::vector<uint8_t> Sha384(const std::vector<uint8_t>& v) { return Sha384(v.data(), v.size()); }
inline std::vector<uint8_t> Sha512(const std::vector<uint8_t>& v) { return Sha512(v.data(), v.size()); }

// Hash by TCG algorithm id. Returns an empty vector for unsupported algorithms
// (e.g. SM3 — Windows CNG has no built-in SM3; the UI shows those as "n/a").
std::vector<uint8_t> HashByAlg(uint16_t alg, const uint8_t* data, size_t len);
inline std::vector<uint8_t> HashByAlg(uint16_t alg, const std::vector<uint8_t>& v) {
    return HashByAlg(alg, v.data(), v.size());
}

// Digest length in bytes for a TCG algorithm id (0 if unknown).
size_t HashSizeByAlg(uint16_t alg);

// Symbolic name: "SHA1"/"SHA256"/"SHA384"/"SHA512"/"SM3_256"/"ALG_0x%04X".
std::string AlgName(uint16_t alg);

} // namespace tcg
