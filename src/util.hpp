// util.hpp — small helpers shared by the parser modules.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace tcg {

// Reader: bounds-checked little-endian reader over a byte buffer.
struct Reader {
    const uint8_t* p = nullptr;
    size_t len = 0;
    size_t off = 0;

    Reader() = default;
    Reader(const uint8_t* data, size_t n) : p(data), len(n) {}

    size_t Remaining() const { return len > off ? len - off : 0; }

    bool U8(uint8_t& v) {
        if (Remaining() < 1) return false;
        v = p[off++];
        return true;
    }
    bool U16(uint16_t& v) {
        if (Remaining() < 2) return false;
        v = uint16_t(p[off]) | (uint16_t(p[off + 1]) << 8);
        off += 2;
        return true;
    }
    bool U32(uint32_t& v) {
        if (Remaining() < 4) return false;
        v = uint32_t(p[off]) | (uint32_t(p[off + 1]) << 8) |
            (uint32_t(p[off + 2]) << 16) | (uint32_t(p[off + 3]) << 24);
        off += 4;
        return true;
    }
    bool U64(uint64_t& v) {
        if (Remaining() < 8) return false;
        v = uint64_t(U32Low(p, off)) | (uint64_t(U32Low(p, off + 4)) << 32);
        off += 8;
        return true;
    }
    bool Bytes(size_t n, const uint8_t** out) {
        if (n > Remaining()) return false;
        *out = p + off;
        off += n;
        return true;
    }
    static uint32_t U32Low(const uint8_t* b, size_t o) {
        return uint32_t(b[o]) | (uint32_t(b[o + 1]) << 8) |
               (uint32_t(b[o + 2]) << 16) | (uint32_t(b[o + 3]) << 24);
    }
};

// Formatting
std::string Format(const char* fmt, ...);
std::string Hex(const uint8_t* data, size_t len);
inline std::string Hex(const std::vector<uint8_t>& v) { return Hex(v.data(), v.size()); }
std::string ShortHex(const uint8_t* b, size_t len);
inline std::string ShortHex(const std::vector<uint8_t>& v) { return ShortHex(v.data(), v.size()); }

// EFI GUID (16 bytes, mixed-endian) -> canonical string
std::string GUIDString(const uint8_t* b);
inline std::string GUIDString(const std::vector<uint8_t>& v) { return GUIDString(v.data()); }
std::string GUIDName(const std::string& guid);
std::string GUIDLabel(const std::string& guid);

// Little-endian UTF-16 -> UTF-8 (stops at the first NUL when stopAtNul).
std::string UTF16ToUTF8(const uint8_t* b, size_t len, bool stopAtNul = true);
inline std::string UTF16ToUTF8(const std::vector<uint8_t>& v, bool stopAtNul = true) {
    return UTF16ToUTF8(v.data(), v.size(), stopAtNul);
}
bool IsPrintable(const std::string& s);

// Lenient DER helpers (X.509 certificates / SubjectPublicKeyInfo).
// DescribeCert  -> "Subject CN (issuer: X, valid until YYYY-MM-DD)"
// DescribeSpki  -> "RSA 2048-bit, sha256=..." / "ECDSA P-256, sha256=..."
std::string DescribeCert(const uint8_t* der, size_t len);
inline std::string DescribeCert(const std::vector<uint8_t>& v) { return DescribeCert(v.data(), v.size()); }
std::string DescribeSpki(const uint8_t* der, size_t len);
inline std::string DescribeSpki(const std::vector<uint8_t>& v) { return DescribeSpki(v.data(), v.size()); }

} // namespace tcg
