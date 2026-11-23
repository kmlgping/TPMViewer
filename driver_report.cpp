// driver_report.cpp — GetRuntimeAttestationReport 两步调用 + 报告包解析。
//
// 调用流程（两步模式）：
//   1) ReportBuffer=NULL, ReportBufferSize=0 → 返回 FALSE +
//      ERROR_INSUFFICIENT_BUFFER，同时 *ReportBufferSize 被填为所需大小。
//      （驱动列表是活的，两次调用之间大小可能漂移 —— 失败就重试几轮。）
//   2) 分配缓冲区后再调一次 → 返回 TRUE，缓冲区里是完整报告包。
//
// 报告包布局（winnt.h SDK 10.0.29648 官方注释）：
//   ┌─ 签名覆盖区（Signed part）──────────────┐
//   │ RUNTIME_REPORT_PACKAGE_HEADER (40B)     │
//   │ Nonce[32]  ← 我们发送、报告回显         │
//   │ N × RUNTIME_REPORT_DIGEST_HEADER (68B)  │ ← 每份报告的 SHA-512
//   └─────────────────────────────────────────┘
//   │ Signature Blob (SignatureSize)          │ ← VTL1 的 RSA-PSS 签名
//   ┌─ 认证区（Authenticated part）───────────┐
//   │ RUNTIME_REPORT_HEADER(8B) + REPORT_BODY │ × NumberOfReports
//   └─────────────────────────────────────────┘
// 各区大小都在包头里（TotalReportDigestsSize / SignatureSize /
// TotalAuthenticatedReportsSize / PackageSize），顺序排列、没有显式 offset
// 字段，解析时按顺序推进并用这些 size 做一致性校验。

#include "driver_report.hpp"

#include "hash.hpp"
#include "util.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#include <cstring>

namespace tcg {
namespace {

// ============================================================================
// 运行时报告结构 —— 按 SDK 10.0.29648 winnt.h 官方布局复刻（本机 SDK 太旧）。
// 不加 #pragma pack：官方头文件用默认对齐，static_assert 锁死大小防手抄错。
// ============================================================================

constexpr UINT32 kPackageMagic = 0x52545250;                 // "RTRP"
constexpr UINT16 kPackageVersionCurrent = 1;                 // 包格式版本
constexpr UINT16 kNonceSize = 32;
constexpr UINT16 kDigestMaxSize = 64;
constexpr UINT16 kSigSchemeSha512RsaPssSha512 = 1;           // 当前唯一签名方案

constexpr UINT16 kReportTypeDriver = 0;                      // RuntimeReportTypeDriver
constexpr UINT64 kDriverReportMask = 1ULL << kReportTypeDriver;

struct RuntimeReportPackageHeader {   // sizeof = 40（尾部补齐到 8 字节对齐）
    UINT32 Magic;
    UINT16 PackageVersion;
    UINT16 NumberOfReports;              // 包里报告种类的数量
    UINT64 ReportTypesBitmap;            // 报告类型位图：1ULL << type
    UINT32 PackageSize;                  // 整个包的大小
    UINT16 ReportDigestType;             // digest 算法（CALG_*，当前 CALG_SHA_512）
    UINT16 TotalReportDigestsSize;       // digest 头数组的总大小
    UINT16 Reserved;
    UINT16 SignatureScheme;              // 签名方案（当前 =1）
    UINT32 SignatureSize;                // 签名 blob 大小
    UINT32 TotalAuthenticatedReportsSize; // 认证区（报告数组）总大小
};

struct RuntimeReportDigestHeader {    // sizeof = 68
    UINT16 ReportType;                   // 这份 digest 对应哪种报告
    UINT16 Reserved;
    UINT8 ReportDigest[kDigestMaxSize];  // 报告（含 8B 头）的 SHA-512
};

struct RuntimeReportHeader {          // sizeof = 8
    UINT16 ReportType;
    UINT16 Reserved;
    UINT32 ReportSize;                   // 本报告总大小（含本头）
};

struct DriverInfoEntry {              // sizeof = 56
    CHAR InternalName[32];               // PE 资源段 InternalName（ANSI，可能截断）
    UINT16 ImageHashAlgorithm;           // 镜像哈希算法（CALG_*）
    UINT16 PublisherThumbprintHashAlgorithm; // 证书指纹算法（CALG_*）
    UINT32 ImageHashOffset;              // → 镜像哈希，相对本报告起始
    UINT32 PublisherThumbprintOffset;    // → 证书指纹，相对本报告起始
    UINT16 LoadCount;                    // 被加载次数
    UINT16 OemNameSize;                  // OEM 名字节数（不含 NUL）
    UINT32 OemNameOffset;                // → OEM 名，相对本报告起始
    union {
        struct {
            UINT16 Unloaded : 1;
            UINT16 BootDriver : 1;
            UINT16 HotPatch : 1;
            UINT16 Reserved : 13;
        };
        UINT16 AsUInt16;
    } Flags;
    UINT16 Padding;
};

struct DriverRuntimeReport {          // 头部固定 12 字节，后面全变长
    RuntimeReportHeader Header;          // 8B
    UINT16 NumberOfDrivers;              // +8
    union {                              // +10
        struct {
            UINT16 ReportOverflowed : 1;
            UINT16 PartialReport : 1;
            UINT16 IncludeBootDrivers : 1;
            UINT16 Reserved : 13;
        };
        UINT16 AsUInt16;
    } Flags;
    // DriverInfoEntry DriverEntries[];  // 从 +12 开始
    // BYTE DynamicBuffer[];             // 条目数组之后：ImageHash/证书指纹/OEM 名
    //                                      的实际数据，全靠上面的 offset 定位
};

static_assert(sizeof(RuntimeReportPackageHeader) == 40, "package header 布局不对");
static_assert(sizeof(RuntimeReportDigestHeader) == 68, "digest header 布局不对");
static_assert(sizeof(RuntimeReportHeader) == 8, "report header 布局不对");
static_assert(sizeof(DriverInfoEntry) == 56, "driver entry 布局不对");
static_assert(sizeof(DriverRuntimeReport) == 12, "driver report 头布局不对");

// API 函数指针 —— 动态加载：旧系统 kernel32 没有这个导出，
// 直接链接会在旧系统上加载失败。
using PFN_GetRuntimeAttestationReport = BOOL(WINAPI*)(
    UCHAR* Nonce, UINT16 PackageVersion, UINT64 ReportTypesBitmap,
    PVOID ReportBuffer, PUINT32 ReportBufferSize);

// ---------------------------------------------------------------------------
// CALG_*（wincrypt.h）→ 算法名 / 摘要长度。
// ALG_CLASS_HASH=(4<<13)=0x8000，ALG_SID_SHA1=4、SHA_256=12、SHA_384=13、
// SHA_512=14，所以 SHA-512 = 0x800E。
// ---------------------------------------------------------------------------
const char* CalgName(UINT16 alg) {
    switch (alg) {
    case 0x8004: return "SHA1";
    case 0x800C: return "SHA-256";
    case 0x800D: return "SHA-384";
    case 0x800E: return "SHA-512";
    default: return nullptr;
    }
}

size_t CalgSize(UINT16 alg) {
    switch (alg) {
    case 0x8004: return 20;
    case 0x800C: return 32;
    case 0x800D: return 48;
    case 0x800E: return 64;
    default: return 0;
    }
}

// 按算法名生成 CALG id 对应的摘要长度；未知算法返回 0。
// 返回错误文本（把 GetLastError 翻译成人话）。
std::string ApiError(const std::string& where, DWORD code) {
    char msg[128];
    if (FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       nullptr, code, 0, msg, sizeof(msg), nullptr)) {
        // 去掉结尾换行
        size_t n = strlen(msg);
        while (n > 0 && (msg[n - 1] == '\n' || msg[n - 1] == '\r' || msg[n - 1] == ' ')) msg[--n] = 0;
        return Format("%s 失败 (Win32 错误 %u: %s)", where.c_str(), code, msg);
    }
    return Format("%s 失败 (Win32 错误 %u)", where.c_str(), code);
}

// 把失败原因翻译成用户能懂的话。
std::string ExplainFailure(DWORD code) {
    switch (code) {
    case ERROR_INVALID_PARAMETER:
        return "系统有这个 API 但拒绝生成报告：需要 Windows 11 25H2+ 且已启用 "
               "VBS / HVCI（内核隔离）。";
    case ERROR_NOT_SUPPORTED:
        return "此 Windows 版本不支持运行时证明报告（需要 Windows 11 25H2+）。";
    default:
        return "驱动报告获取失败，系统可能不满足运行条件（需 Win11 25H2 + VBS/HVCI）。";
    }
}

std::string ToHex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) {
        s.push_back(d[p[i] >> 4]);
        s.push_back(d[p[i] & 15]);
    }
    return s;
}

} // namespace

// ============================================================================
// 主入口：拉取 + 解析。
// ============================================================================
bool FetchDriverReport(DriverReportResult* out, std::string* err) {
    // ---- 1. 动态加载 API。找不到 = 系统版本低于 25H2。----
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32) {
        if (err) *err = "GetModuleHandleW(kernel32) 失败";
        return false;
    }
    auto fn = reinterpret_cast<PFN_GetRuntimeAttestationReport>(
        reinterpret_cast<void*>(GetProcAddress(k32, "GetRuntimeAttestationReport")));
    if (!fn) {
        if (err) *err = "此 Windows 版本没有 GetRuntimeAttestationReport 导出"
                        "（运行时证明 API 需要 Windows 11 25H2 及以上）。";
        return false;
    }

    // ---- 2. 生成 32 字节随机 nonce（防重放；报告会把它原样带回）。----
    UCHAR nonce[kNonceSize];
    if (FAILED(BCryptGenRandom(nullptr, nonce, sizeof(nonce),
                               BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        // 系统首选 RNG 不可用时退回飞行 RNG 标志再试一次。
        if (FAILED(BCryptGenRandom(nullptr, nonce, sizeof(nonce),
                                   BCRYPT_USE_SYSTEM_PREFERRED_RNG |
                                       BCRYPT_RNG_USE_ENTROPY_IN_REG))) {
            if (err) *err = "BCryptGenRandom 生成 nonce 失败";
            return false;
        }
    }

    // ---- 3. 两步调用：先查大小，再真取；大小漂移就重试。----
    std::vector<uint8_t> buf;
    for (int attempt = 0; attempt < 4; attempt++) {
        UINT32 size = 0;
        SetLastError(0);
        if (!fn(nonce, kPackageVersionCurrent, kDriverReportMask, nullptr, &size)) {
            DWORD code = GetLastError();
            if (code != ERROR_INSUFFICIENT_BUFFER) {
                if (err) *err = ExplainFailure(code) + " [" + ApiError("查询报告大小", code) + "]";
                return false;
            }
            if (size == 0) {
                if (err) *err = "API 返回的报告大小为 0（异常状态）。";
                return false;
            }
        }
        buf.resize(size);
        SetLastError(0);
        if (fn(nonce, kPackageVersionCurrent, kDriverReportMask, buf.data(), &size)) {
            buf.resize(size); // 第二次调用可能刷新实际大小
            break;
        }
        DWORD code = GetLastError();
        if (code != ERROR_INSUFFICIENT_BUFFER) {
            if (err) *err = ExplainFailure(code) + " [" + ApiError("获取报告", code) + "]";
            return false;
        }
        // 大小漂移 → 用新大小重试
    }
    if (buf.empty()) {
        if (err) *err = "多次重试后仍未获取到报告（大小持续漂移）。";
        return false;
    }

    // ---- 4. 解析报告包。----
    *out = DriverReportResult{};
    out->packageSize = buf.size();
    std::string note;

    const uint8_t* base = buf.data();
    size_t total = buf.size();

    if (total < sizeof(RuntimeReportPackageHeader) + kNonceSize) {
        if (err) *err = "报告包太小，连包头都放不下。";
        return false;
    }
    const auto* pkg = reinterpret_cast<const RuntimeReportPackageHeader*>(base);
    if (pkg->Magic != kPackageMagic) {
        if (err) *err = Format("报告包 Magic 错误：0x%08X（应为 0x%08X \"RTRP\"）。",
                               pkg->Magic, kPackageMagic);
        return false;
    }
    if (pkg->PackageVersion != kPackageVersionCurrent) {
        note += Format("包版本 %u 与已知版本 %u 不同，解析可能不准确。 ",
                       pkg->PackageVersion, kPackageVersionCurrent);
    }
    if (pkg->SignatureScheme != kSigSchemeSha512RsaPssSha512) {
        note += Format("未知签名方案 %u（已知 =1 SHA512-RSA-PSS）。 ", pkg->SignatureScheme);
    }

    // 按顺序推算各分区边界。
    const size_t kHeaderSize = sizeof(RuntimeReportPackageHeader); // 40
    const size_t nonceOff = kHeaderSize;
    const size_t digestsOff = nonceOff + kNonceSize;
    const size_t digestCount = pkg->TotalReportDigestsSize / sizeof(RuntimeReportDigestHeader);
    const size_t signatureOff = digestsOff + pkg->TotalReportDigestsSize;
    const size_t reportsOff = signatureOff + pkg->SignatureSize;
    const size_t reportsEnd = reportsOff + pkg->TotalAuthenticatedReportsSize;

    // 一致性校验：报告区结束 = 包大小；各分区都要落在包内。
    if (reportsEnd > total || pkg->PackageSize != total) {
        if (err) *err = Format("报告包大小不一致：PackageSize=%u 实际=%zu 认证区结束=%zu。",
                               pkg->PackageSize, total, reportsEnd);
        return false;
    }
    if (digestCount * sizeof(RuntimeReportDigestHeader) != pkg->TotalReportDigestsSize) {
        note += Format("digest 区大小 %u 不是 %zu 的整数倍。 ",
                       pkg->TotalReportDigestsSize, sizeof(RuntimeReportDigestHeader));
    }

    // nonce 回显校验：报告必须带回来我们刚发的那串。
    if (memcmp(base + nonceOff, nonce, kNonceSize) != 0) {
        note += "报告回显的 nonce 与请求不匹配（理论上不该发生）。 ";
    }
    out->nonceHex = ToHex(base + nonceOff, kNonceSize);

    // digest 校验：对认证区里每份报告算 SHA-512，与签名覆盖区的 digest 比对。
    // 证明"报告体 = 被签名的内容"（本工具不验 VTL1 签名本身 —— 那需要
    // 微软 IDKS 证书链；结构完整性和 digest 一致性在这里检查）。
    if (digestCount > 0 && pkg->ReportDigestType == 0x800E) { // CALG_SHA_512
        size_t off = reportsOff;
        int verified = 0, mismatched = 0;
        while (off + sizeof(RuntimeReportHeader) <= reportsEnd) {
            const auto* rh = reinterpret_cast<const RuntimeReportHeader*>(base + off);
            if (rh->ReportSize < sizeof(RuntimeReportHeader) ||
                off + rh->ReportSize > reportsEnd)
                break; // 报告体越界 → 包损坏，后面靠 note 说明
            auto actual = Sha512(base + off, rh->ReportSize);
            for (size_t i = 0; i < digestCount; i++) {
                const auto* dh = reinterpret_cast<const RuntimeReportDigestHeader*>(
                    base + digestsOff + i * sizeof(RuntimeReportDigestHeader));
                if (dh->ReportType != rh->ReportType) continue;
                if (memcmp(actual.data(), dh->ReportDigest, 64) == 0) verified++;
                else mismatched++;
                break;
            }
            off += rh->ReportSize;
        }
        if (mismatched > 0)
            note += Format("digest 校验：%d 份匹配，%d 份不匹配（报告体与签名区不一致）。 ",
                           verified, mismatched);
        else if (verified > 0)
            note += Format("digest 校验：%d/%d 份匹配。 ", verified, int(digestCount));
    }

    // ---- 5. 遍历认证区，找 driver report。----
    bool found = false;
    size_t off = reportsOff;
    while (off + sizeof(RuntimeReportHeader) <= reportsEnd) {
        const auto* rh = reinterpret_cast<const RuntimeReportHeader*>(base + off);
        if (rh->ReportSize < sizeof(RuntimeReportHeader) || off + rh->ReportSize > reportsEnd) {
            note += Format("偏移 0x%zX 处报告头越界（ReportSize=%u），停止解析。 ",
                           off, rh->ReportSize);
            break;
        }
        if (rh->ReportType == kReportTypeDriver) {
            found = true;
            // 报告起始 = RUNTIME_REPORT_HEADER 所在位置；
            // 条目里的 ImageHashOffset 等都是相对这个位置。
            const size_t reportStart = off;
            const size_t reportSize = rh->ReportSize;
            if (reportSize < sizeof(DriverRuntimeReport)) {
                note += "driver report 太小，无法容纳固定头。 ";
            } else {
                const auto* drv = reinterpret_cast<const DriverRuntimeReport*>(base + reportStart);
                out->reportOverflowed = drv->Flags.ReportOverflowed != 0;
                out->partialReport = drv->Flags.PartialReport != 0;
                out->includeBootDrivers = drv->Flags.IncludeBootDrivers != 0;

                const size_t maxDrivers =
                    (reportSize - sizeof(DriverRuntimeReport)) / sizeof(DriverInfoEntry);
                const size_t count =
                    drv->NumberOfDrivers <= maxDrivers ? drv->NumberOfDrivers : maxDrivers;
                if (count != drv->NumberOfDrivers)
                    note += Format("报告声称 %u 个驱动，实际空间只够 %zu 个。 ",
                                   drv->NumberOfDrivers, count);

                out->drivers.reserve(count);
                for (size_t i = 0; i < count; i++) {
                    const auto* e = reinterpret_cast<const DriverInfoEntry*>(
                        base + reportStart + sizeof(DriverRuntimeReport) +
                        i * sizeof(DriverInfoEntry));

                    DriverEntryView v;
                    // CHAR[32]：找 NUL；没有 NUL（名字正好 32 字节）就整段取。
                    size_t nameLen = 0;
                    while (nameLen < 32 && e->InternalName[nameLen] != '\0') nameLen++;
                    v.internalName.assign(e->InternalName, nameLen);

                    v.loadCount = e->LoadCount;
                    v.unloaded = e->Flags.Unloaded != 0;
                    v.bootDriver = e->Flags.BootDriver != 0;
                    v.hotPatchable = e->Flags.HotPatch != 0;

                    // 镜像哈希：offset + 算法长度都要落在报告内。
                    if (const char* an = CalgName(e->ImageHashAlgorithm)) {
                        v.imageHashAlg = an;
                        size_t hs = CalgSize(e->ImageHashAlgorithm);
                        if (e->ImageHashOffset + hs <= reportSize)
                            v.imageHash = ToHex(base + reportStart + e->ImageHashOffset, hs);
                        else
                            v.imageHash = "(越界)";
                    } else {
                        v.imageHashAlg = Format("CALG 0x%04X", e->ImageHashAlgorithm);
                    }

                    // 签名叶证书指纹。
                    if (const char* an = CalgName(e->PublisherThumbprintHashAlgorithm)) {
                        v.certThumbAlg = an;
                        size_t ts = CalgSize(e->PublisherThumbprintHashAlgorithm);
                        if (e->PublisherThumbprintOffset + ts <= reportSize)
                            v.certThumb = ToHex(base + reportStart + e->PublisherThumbprintOffset, ts);
                        else
                            v.certThumb = "(越界)";
                    } else {
                        v.certThumbAlg = Format("CALG 0x%04X", e->PublisherThumbprintHashAlgorithm);
                    }

                    // OEM 名（OPUS 块，ANSI 字节串）。
                    if (e->OemNameSize > 0) {
                        if (e->OemNameOffset + e->OemNameSize <= reportSize)
                            v.oemName.assign(reinterpret_cast<const char*>(
                                                 base + reportStart + e->OemNameOffset),
                                             e->OemNameSize);
                        else
                            v.oemName = "(越界)";
                    }
                    out->drivers.push_back(std::move(v));
                }
            }
            break; // 只要了 driver report，找到即可
        }
        off += rh->ReportSize;
    }

    if (!found) {
        if (err) *err = "报告包里没有 driver report（请求与响应类型不匹配）。";
        return false;
    }

    if (!out->reportOverflowed && !out->partialReport)
        note += "报告声称已包含全部记录在案的驱动。";
    out->packageNote = note;
    return true;
}

} // namespace tcg
