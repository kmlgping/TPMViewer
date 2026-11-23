// util.cpp — implementations for the helpers declared in util.hpp.
#include "util.hpp"
#include "hash.hpp"

#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace tcg {

std::string Format(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    va_list args2;
    va_copy(args2, args);
    int n = vsnprintf(nullptr, 0, fmt, args);
    va_end(args);
    std::string out;
    if (n > 0) {
        out.resize(size_t(n));
        vsnprintf(out.data(), size_t(n) + 1, fmt, args2);
    }
    va_end(args2);
    return out;
}

std::string Hex(const uint8_t* data, size_t len) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0F]);
    }
    return out;
}

std::string ShortHex(const uint8_t* b, size_t len) {
    if (len <= 48) return Hex(b, len);
    return Hex(b, 48) + Format("... (共 %zu 字节)", len);
}

std::string GUIDString(const uint8_t* b) {
    if (!b) return "";
    // EFI GUID is mixed-endian: first 3 fields little-endian, rest big-endian.
    return Format("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                  Reader::U32Low(b, 0),
                  uint32_t(b[4]) | (uint32_t(b[5]) << 8),
                  uint32_t(b[6]) | (uint32_t(b[7]) << 8),
                  b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

std::string GUIDName(const std::string& guid) {
    static const struct { const char* g; const char* n; } known[] = {
        {"8be4df61-93ca-11d2-aa0d-00e098032b8c", "EFI_GLOBAL_VARIABLE"},
        {"d719b2cb-3d3a-4596-a3bc-dad00e67656f", "EFI_IMAGE_SECURITY_DATABASE"},
        {"a5c059a1-94e4-4aa7-87b5-ab155c2bf072", "EFI_CERT_X509"},
        {"c1c41626-504c-4092-aca9-41f936934328", "EFI_CERT_SHA256"},
        {"3c5766e8-269c-4e34-aa14-ed776e85b3b6", "EFI_CERT_RSA2048"},
        {"826ca512-cf10-4ac9-b187-be01496631bd", "EFI_CERT_SHA1"},
        {"3bd2a492-96c0-4079-b420-fcf98ef103ed", "EFI_CERT_X509_SHA256"},
        {"7076876e-80c2-4ee6-aad2-28b349a6865b", "EFI_CERT_X509_SHA384"},
        {"446dbf63-2502-4cda-bcfa-2465d2b0fe9d", "EFI_CERT_X509_SHA512"},
        {"ff3e5307-9fd0-48c9-85f1-8ad56c701e01", "EFI_CERT_SHA384"},
        {"093e0fae-a6c4-4f50-9f1b-d41e2b89c19a", "EFI_CERT_SHA512"},
        {"77fa9abd-0359-4d32-bd60-28f4e78f784b", "微软厂商 (dbDefault/dbxDefault 所有者)"},
        {"c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "EFI 系统分区 (ESP)"},
        {"e3c9e316-0b5c-4db8-817d-f92df00215ae", "Microsoft 保留分区 (MSR)"},
        {"ebd0a0a2-b9e5-4433-87c0-68b6b72699c7", "基本数据分区"},
        {"de94bba4-06d1-4d40-a16a-bfd50179d6ac", "Windows 恢复分区 (WinRE)"},
        {"0fc63daf-8483-4772-8e79-3d69d8477de4", "Linux 文件系统"},
        {"21686148-6449-6e6f-744e-656564454649", "BIOS 启动分区 (Grub)"},
        {"8868e871-e4f1-11d3-bc22-0080c73c8881", "ACPI 2.0+ 表 (RSDP)"},
        {"eb9d2d30-2d88-11d3-9a16-0090273fc14d", "ACPI 1.0 表"},
        {"eb9d2d31-2d88-11d3-9a16-0090273fc14d", "SMBIOS 表"},
        {"f2fd1544-9794-4a2c-992e-e5bbcf20e394", "SMBIOS 3 表"},
        {"eb9d2d32-2d88-11d3-9a16-0090273fc14d", "SAL 系统表"},
        {"eb9d2d2f-2d88-11d3-9a16-0090273fc14d", "MPS 表"},
        {"605dab50-e046-4300-abb6-3dd810dd8b23", "Shim 引导 (EV_EFI_VARIABLE_AUTHORITY 签发者)"},
    };
    for (auto& k : known) {
        if (_stricmp(guid.c_str(), k.g) == 0) return k.n;
    }
    return "";
}

std::string GUIDLabel(const std::string& guid) {
    std::string n = GUIDName(guid);
    if (n.empty()) return guid;
    return n + " (" + guid + ")";
}

std::string UTF16ToUTF8(const uint8_t* b, size_t len, bool stopAtNul) {
    std::string out;
    if (!b) return out;
    auto appendCp = [&out](uint32_t cp) {
        if (cp < 0x80) {
            out.push_back(char(cp));
        } else if (cp < 0x800) {
            out.push_back(char(0xC0 | (cp >> 6)));
            out.push_back(char(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(char(0xE0 | (cp >> 12)));
            out.push_back(char(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(char(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(char(0xF0 | (cp >> 18)));
            out.push_back(char(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(char(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(char(0x80 | (cp & 0x3F)));
        }
    };
    size_t n = len & ~size_t(1); // whole UTF-16 code units
    size_t i = 0;
    while (i + 1 < n) {
        uint16_t c = uint16_t(b[i]) | (uint16_t(b[i + 1]) << 8);
        i += 2;
        if (stopAtNul && c == 0) break;
        uint32_t cp = c;
        if (c >= 0xD800 && c <= 0xDBFF) { // high surrogate: pair with the next low one
            if (i + 1 < n) {
                uint16_t lo = uint16_t(b[i]) | (uint16_t(b[i + 1]) << 8);
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    cp = 0x10000 + ((uint32_t(c) - 0xD800) << 10) + (lo - 0xDC00);
                    i += 2;
                } else {
                    cp = 0xFFFD;
                }
            } else {
                cp = 0xFFFD;
            }
        } else if (c >= 0xDC00 && c <= 0xDFFF) {
            cp = 0xFFFD; // orphan low surrogate
        }
        appendCp(cp);
    }
    return out;
}

bool IsPrintable(const std::string& s) {
    if (s.empty()) return false;
    for (size_t i = 0; i < s.size(); i++) {
        unsigned char c = s[i];
        if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') return false;
        if (c == 0x7F) return false;
        // U+FFFD (replacement char) marks broken UTF-16 -> treat as not printable.
        if (c == 0xEF && i + 2 < s.size() &&
            (unsigned char)s[i + 1] == 0xBF && (unsigned char)s[i + 2] == 0xBD) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Lenient DER walking
// ---------------------------------------------------------------------------

namespace {

struct DerView {
    const uint8_t* p = nullptr;
    size_t n = 0;
};

// Reads one definite-length TLV at p; advances p past it.
bool DerNext(const uint8_t*& p, const uint8_t* end, uint8_t& tag, DerView& v) {
    if (size_t(end - p) < 2) return false;
    tag = *p++;
    uint8_t b = *p++;
    if (b & 0x80) {
        int num = b & 0x7F;
        if (num == 0 || num > 4) return false;
        if (size_t(end - p) < size_t(num)) return false;
        size_t l = 0;
        for (int i = 0; i < num; i++) l = (l << 8) | p[i];
        p += num;
        if (size_t(end - p) < l) return false;
        v.p = p; v.n = l; p += l;
    } else {
        if (size_t(end - p) < size_t(b)) return false;
        v.p = p; v.n = b; p += b;
    }
    return true;
}

bool OidIs(const uint8_t* oid, size_t n, const uint8_t* ref, size_t rn) {
    return n == rn && memcmp(oid, ref, rn) == 0;
}
const uint8_t kOidCn[]      = {0x55, 0x04, 0x03};
const uint8_t kOidRsa[]     = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
const uint8_t kOidEcPub[]   = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
const uint8_t kOidP256[]    = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
const uint8_t kOidP384[]    = {0x2B, 0x81, 0x04, 0x00, 0x22};
const uint8_t kOidP521[]    = {0x2B, 0x81, 0x04, 0x00, 0x23};

// Decodes an ASN.1 directory string value into UTF-8.
std::string DerStringValue(uint8_t tag, const uint8_t* b, size_t n) {
    if (tag == 0x1E) { // BMPString = UTF-16 big endian
        std::string out;
        for (size_t i = 0; i + 1 < n; i += 2) {
            uint16_t c = (uint16_t(b[i]) << 8) | b[i + 1];
            if (c < 0x80) out.push_back(char(c));
            else if (c < 0x800) {
                out.push_back(char(0xC0 | (c >> 6)));
                out.push_back(char(0x80 | (c & 0x3F)));
            } else {
                out.push_back(char(0xE0 | (c >> 12)));
                out.push_back(char(0x80 | ((c >> 6) & 0x3F)));
                out.push_back(char(0x80 | (c & 0x3F)));
            }
        }
        return out;
    }
    // Printable/UTF8/IA5/Teletex: raw bytes (UTF-8 or ASCII passthrough).
    return std::string(reinterpret_cast<const char*>(b), n);
}

// First commonName inside a DER Name (RDNSequence).
std::string DerFirstCN(const DerView& name) {
    const uint8_t* p = name.p;
    const uint8_t* end = name.p + name.n;
    uint8_t tag;
    DerView rdn;
    while (DerNext(p, end, tag, rdn)) { // SET
        const uint8_t* q = rdn.p;
        const uint8_t* qe = rdn.p + rdn.n;
        uint8_t t2;
        DerView atv;
        while (DerNext(q, qe, t2, atv)) { // SEQUENCE { OID, value }
            const uint8_t* r = atv.p;
            const uint8_t* re = atv.p + atv.n;
            uint8_t t3;
            DerView oid, val;
            if (!DerNext(r, re, t3, oid)) break;
            if (!DerNext(r, re, t3, val)) break;
            if (t3 == 0x06 && OidIs(oid.p, oid.n, kOidCn, sizeof(kOidCn))) {
                std::string s = DerStringValue(val.p ? t3 : t3, val.p, val.n);
                // t3 now holds the tag of the value TLV (second DerNext call).
                return s;
            }
        }
    }
    return "";
}

// notAfter from a DER Validity SEQUENCE.
std::string DerNotAfter(const DerView& validity) {
    const uint8_t* p = validity.p;
    const uint8_t* end = validity.p + validity.n;
    uint8_t tag;
    DerView t[2];
    int idx = 0;
    while (idx < 2 && DerNext(p, end, tag, t[idx])) idx++;
    if (idx < 2) return "";
    const uint8_t* s = t[1].p;
    size_t n = t[1].n;
    if (tag == 0x17 && n >= 6) { // UTCTime yyMMddHHmmss...
        int yy = (s[0] - '0') * 10 + (s[1] - '0');
        return Format("%s%02d-%c%c-%c%c", yy >= 50 ? "19" : "20", yy, s[2], s[3], s[4], s[5]);
    }
    if (tag == 0x18 && n >= 8) { // GeneralizedTime yyyyMMddHHmmss...
        return std::string(reinterpret_cast<const char*>(s), 8)
            .insert(4, "-").insert(7, "-");
    }
    return "";
}

} // namespace

std::string DescribeCert(const uint8_t* der, size_t len) {
    if (!der || len < 16) return "";
    const uint8_t* p = der;
    const uint8_t* end = der + len;
    uint8_t tag;
    DerView outer, tbs;
    if (!DerNext(p, end, tag, outer) || tag != 0x30) return "";
    p = outer.p; end = outer.p + outer.n;
    if (!DerNext(p, end, tag, tbs) || tag != 0x30) return "";

    p = tbs.p; end = tbs.p + tbs.n;
    DerView issuer, subject, validity;
    bool haveI = false, haveS = false, haveV = false;
    while (p < end) {
        uint8_t t;
        DerView v;
        if (!DerNext(p, end, t, v)) break;
        if (t == 0xA0) continue;              // [0] version
        if (t == 0x02) continue;              // serialNumber
        if (t == 0x30 && !haveI && !haveS && !haveV) { // signature algorithm first
            continue;
        }
        if (t == 0x30 && !haveI) { issuer = v; haveI = true; continue; }
        if (t == 0x30 && !haveV) { validity = v; haveV = true; continue; }
        if (t == 0x30 && !haveS) { subject = v; haveS = true; break; }
    }
    if (!haveS) return "";

    std::string subj = DerFirstCN(subject);
    std::string iss = DerFirstCN(issuer);
    std::string na = haveV ? DerNotAfter(validity) : "";
    if (subj.empty()) {
        auto sum = Sha256(der, len);
        return Format("X.509 (无法解析), sha256=%s", Hex(sum).substr(0, 16).c_str());
    }
    if (iss.empty()) iss = "?";
    if (na.empty()) na = "?";
    return Format("%s (签发者: %s，有效期至 %s)", subj.c_str(), iss.c_str(), na.c_str());
}

std::string DescribeSpki(const uint8_t* der, size_t len) {
    auto sum = Sha256(der, len);
    std::string sha = Hex(sum);
    if (!der || len < 10) return Format("%d 字节密钥, sha256=%s", int(len), sha.c_str());
    const uint8_t* p = der;
    const uint8_t* end = der + len;
    uint8_t tag;
    DerView outer, algid, bits;
    if (!DerNext(p, end, tag, outer) || tag != 0x30) {
        return Format("%d 字节密钥, sha256=%s", int(len), sha.c_str());
    }
    p = outer.p; end = outer.p + outer.n;
    if (!DerNext(p, end, tag, algid) || tag != 0x30) {
        return Format("%d 字节密钥, sha256=%s", int(len), sha.c_str());
    }
    if (!DerNext(p, end, tag, bits) || tag != 0x03) {
        return Format("%d 字节密钥, sha256=%s", int(len), sha.c_str());
    }
    // AlgorithmIdentifier: OID [+ params OID]
    const uint8_t* q = algid.p;
    const uint8_t* qe = algid.p + algid.n;
    uint8_t t2; DerView oid, param;
    bool haveOid = DerNext(q, qe, t2, oid);
    bool haveParam = haveOid && DerNext(q, qe, t2, param);
    if (!haveOid) return Format("%d 字节密钥, sha256=%s", int(len), sha.c_str());

    if (OidIs(oid.p, oid.n, kOidRsa, sizeof(kOidRsa))) {
        // BIT STRING: 00 || SEQUENCE { modulus INTEGER, e INTEGER }
        if (bits.n < 4) return Format("RSA, sha256=%s", sha.c_str());
        const uint8_t* r = bits.p + 1; // skip unused-bits byte
        const uint8_t* re = bits.p + bits.n;
        uint8_t t3; DerView inner, modulus;
        if (!DerNext(r, re, t3, inner) || t3 != 0x30) return Format("RSA, sha256=%s", sha.c_str());
        const uint8_t* m = inner.p;
        const uint8_t* me = inner.p + inner.n;
        if (!DerNext(m, me, t3, modulus) || t3 != 0x02) return Format("RSA, sha256=%s", sha.c_str());
        const uint8_t* mb = modulus.p;
        size_t mn = modulus.n;
        if (mn > 0 && mb[0] == 0) { mb++; mn--; } // ASN.1 sign padding
        int lz = 0;
        if (mn > 0 && mb[0] != 0) {
            for (int bit = 7; bit >= 0 && !(mb[0] & (1 << bit)); bit--) lz++;
        }
        long long bitlen = (long long)(mn * 8) - lz;
        return Format("RSA %lld 位, sha256=%s", bitlen, sha.c_str());
    }
    if (OidIs(oid.p, oid.n, kOidEcPub, sizeof(kOidEcPub))) {
        const char* curve = "EC";
        if (haveParam && OidIs(param.p, param.n, kOidP256, sizeof(kOidP256))) curve = "P-256";
        else if (haveParam && OidIs(param.p, param.n, kOidP384, sizeof(kOidP384))) curve = "P-384";
        else if (haveParam && OidIs(param.p, param.n, kOidP521, sizeof(kOidP521))) curve = "P-521";
        return Format("ECDSA %s, sha256=%s", curve, sha.c_str());
    }
    return Format("%d 字节密钥, sha256=%s", int(len), sha.c_str());
}

} // namespace tcg
