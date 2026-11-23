// ============================================================================
//  sipa.cpp —— 解析微软 SIPA 度量数据（学习注解版）
// ============================================================================
//
// 【SIPA 是什么】
//   SIPA = System Integrity Policy Attestation，Windows 启动管理器（bootmgr）
//   自己发明的一种度量数据格式。它把"这次启动我按什么策略来跑"的细节
//   （代码完整性开没开、测试签名开没开、加载了哪些驱动模块、BitLocker
//   用什么方式解锁的……）用统一的 TLV 格式记下来，塞进事件日志的
//   EV_NO_ACTION / EV_EVENT_TAG 事件里（见 tcg_log.cpp 的 DecodeNoAction /
//   DecodeEventTag）。
//
//   和 TCG 标准事件比，SIPA 的信息细得多：TCG 只告诉你"加载了 bootmgr"，
//   SIPA 能告诉你"bootmgr 是谁签名的、Authenticode 哈希是多少、驱动加载
//   策略是哪档"。
//
// 【TLV 字节布局】（字节序：小端 LE）
//   每个元素 = 头 + 数据体，头 8 字节：
//   ┌────────────────────┬──────────────┬─────────────────────┐
//   │ type 4B (LE)       │ size 4B (LE) │ body（size 字节）   │
//   └────────────────────┴──────────────┴─────────────────────┘
//
// 【type 字段的位布局】—— 一个数里塞了三层含义：
//   ┌────┬──────────────┬──────────────────┬──────────────────┐
//   │bit31│bit30         │bit23..16         │bit15..0          │
//   │保留│AGGREGATION 标志│ 分类（cat）      │ 具体编号         │
//   └────┴──────────────┴──────────────────┴──────────────────┘
//   · bit30 (kAggregation)：1=容器（body 里面又是若干个同样的 TLV，
//     递归嵌套），0=叶子（body 是值，按 type 解释成数字/文本/哈希）
//   · 分类（kCat* 常量）：这个信息属于哪一类 —— OS 参数 / 加载的模块 /
//     授权密钥 / ELAM / VBS / DRTM……
//   · 编号：分类里具体是哪个字段（如 OSPARAMETER 类的 0x0002=CodeIntegrity）
//
// 【解析策略】
//   1) DecodeSipaInner 按头切 TLV；bit30=1 就递归解析 body 当子容器
//   2) 叶子节点调 FormatSipaValue 按已知 type 翻译成人话
//   3) SipaLooksValid 用来"验货"：要求字节数刚好对得上 + 至少认得一个
//      type —— 因为 DecodeNoAction 里只是"试探性"解析，得防误判
// ============================================================================
// sipa.cpp — SIPA TLV decoding, translated from BootViewer's internal/tcglog/sipa.go.
#include "sipa.hpp"
#include "hash.hpp"
#include "util.hpp"

#include <cstring>
#include <functional>
#include <string>
#include <vector>

namespace tcg {

namespace {

// bit30：置 1 表示这是"容器"元素，body 里嵌套的是子 TLV（递归）。
constexpr uint32_t kAggregation = 0x40000000;

// 分类段（type 的 bit16~23）。SIPA 事件都长一个样，靠分类区分语义：
constexpr uint32_t kCatContainer      = 0x00010000; // 容器/信任边界
constexpr uint32_t kCatInformation    = 0x00020000; // 信息类（启动计数器等）
constexpr uint32_t kCatError          = 0x00030000;
constexpr uint32_t kCatPreOSParameter = 0x00040000; // OS 启动前参数
constexpr uint32_t kCatOSParameter    = 0x00050000; // OS 启动参数（BCD 那套）
constexpr uint32_t kCatAuthority      = 0x00060000; // 授权密钥
constexpr uint32_t kCatLoadedModule   = 0x00070000; // 加载模块的细节
constexpr uint32_t kCatTrustPoint     = 0x00080000; // TPM Quote 等信任点
constexpr uint32_t kCatELAM           = 0x00090000; // 反恶意软件早期启动
constexpr uint32_t kCatVBS            = 0x000A0000; // 基于虚拟化的安全
constexpr uint32_t kCatKSR            = 0x000B0000; // 内核签名吊销
constexpr uint32_t kCatDRTM           = 0x000C0000; // 动态度量根

// Well-known SIPA identifiers (aggregation | category | id).
constexpr uint32_t SipaTrustBoundary          = kAggregation | kCatContainer | 0x0001;
constexpr uint32_t SipaELAMAggregation        = kAggregation | kCatContainer | 0x0002;
constexpr uint32_t SipaLoadedModuleAggr       = kAggregation | kCatContainer | 0x0003;
constexpr uint32_t SipaTrustpointAggregation  = kAggregation | kCatContainer | 0x0004;
constexpr uint32_t SipaKSRAggregation         = kAggregation | kCatContainer | 0x0005;
constexpr uint32_t SipaKSRSignedMeasurement   = kAggregation | kCatContainer | 0x0006;
constexpr uint32_t SipaInformation            = kCatInformation | 0x0001;
constexpr uint32_t SipaBootCounter            = kCatInformation | 0x0002;
constexpr uint32_t SipaTransferControl        = kCatInformation | 0x0003;
constexpr uint32_t SipaApplicationReturn      = kCatInformation | 0x0004;
constexpr uint32_t SipaBitlockerUnlock        = kCatInformation | 0x0005;
constexpr uint32_t SipaEventCounter           = kCatInformation | 0x0006;
constexpr uint32_t SipaCounterID              = kCatInformation | 0x0007;
constexpr uint32_t SipaMORBitNotCancelable    = kCatInformation | 0x0008;
constexpr uint32_t SipaApplicationSVN         = kCatInformation | 0x0009;
constexpr uint32_t SipaSVNChainStatus         = kCatInformation | 0x000A;
constexpr uint32_t SipaMORBitAPIStatus        = kCatInformation | 0x000B;
constexpr uint32_t SipaBootDebugging          = kCatPreOSParameter | 0x0001;
constexpr uint32_t SipaBootRevocationList     = kCatPreOSParameter | 0x0002;
constexpr uint32_t SipaOSKernelDebug          = kCatOSParameter | 0x0001;
constexpr uint32_t SipaCodeIntegrity          = kCatOSParameter | 0x0002;
constexpr uint32_t SipaTestSigning            = kCatOSParameter | 0x0003;
constexpr uint32_t SipaDEP                    = kCatOSParameter | 0x0004;
constexpr uint32_t SipaSafeMode               = kCatOSParameter | 0x0005;
constexpr uint32_t SipaWinPE                  = kCatOSParameter | 0x0006;
constexpr uint32_t SipaPAE                    = kCatOSParameter | 0x0007;
constexpr uint32_t SipaOSDevice               = kCatOSParameter | 0x0008;
constexpr uint32_t SipaSystemRoot             = kCatOSParameter | 0x0009;
constexpr uint32_t SipaHypervisorLaunchType   = kCatOSParameter | 0x000A;
constexpr uint32_t SipaHypervisorPath         = kCatOSParameter | 0x000B;
constexpr uint32_t SipaHypervisorIOMMUPolicy  = kCatOSParameter | 0x000C;
constexpr uint32_t SipaHypervisorDebug        = kCatOSParameter | 0x000D;
constexpr uint32_t SipaDriverLoadPolicy       = kCatOSParameter | 0x000E;
constexpr uint32_t SipaSIPolicy               = kCatOSParameter | 0x000F;
constexpr uint32_t SipaHypervisorMMIONXPolicy = kCatOSParameter | 0x0010;
constexpr uint32_t SipaHypervisorMSRFilter    = kCatOSParameter | 0x0011;
constexpr uint32_t SipaVSMLaunchType          = kCatOSParameter | 0x0012;
constexpr uint32_t SipaOSRevocationList       = kCatOSParameter | 0x0013;
constexpr uint32_t SipaSMTStatus              = kCatOSParameter | 0x0014;
constexpr uint32_t SipaVSMIDKInfo             = kCatOSParameter | 0x0020;
constexpr uint32_t SipaFlightSigning          = kCatOSParameter | 0x0021;
constexpr uint32_t SipaPagefileEncryption     = kCatOSParameter | 0x0022;
constexpr uint32_t SipaVSMIDKSInfo            = kCatOSParameter | 0x0023;
constexpr uint32_t SipaHibernationDisabled    = kCatOSParameter | 0x0024;
constexpr uint32_t SipaDumpsDisabled          = kCatOSParameter | 0x0025;
constexpr uint32_t SipaDumpEncryptionEnabled  = kCatOSParameter | 0x0026;
constexpr uint32_t SipaDumpEncryptionKey      = kCatOSParameter | 0x0027;
constexpr uint32_t SipaLSAISOConfig           = kCatOSParameter | 0x0028;
constexpr uint32_t SipaSIPolicySigner         = kCatOSParameter | 0x0031;
constexpr uint32_t SipaNoAuthority            = kCatAuthority | 0x0001;
constexpr uint32_t SipaAuthorityPubKey        = kCatAuthority | 0x0002;
constexpr uint32_t SipaFilePath               = kCatLoadedModule | 0x0001;
constexpr uint32_t SipaImageSize              = kCatLoadedModule | 0x0002;
constexpr uint32_t SipaHashAlgorithmID        = kCatLoadedModule | 0x0003;
constexpr uint32_t SipaAuthenticodeHash       = kCatLoadedModule | 0x0004;
constexpr uint32_t SipaAuthorityIssuer        = kCatLoadedModule | 0x0005;
constexpr uint32_t SipaAuthoritySerial        = kCatLoadedModule | 0x0006;
constexpr uint32_t SipaImageBase              = kCatLoadedModule | 0x0007;
constexpr uint32_t SipaAuthorityPublisher     = kCatLoadedModule | 0x0008;
constexpr uint32_t SipaAuthoritySHA1Thumb     = kCatLoadedModule | 0x0009;
constexpr uint32_t SipaImageValidated         = kCatLoadedModule | 0x000A;
constexpr uint32_t SipaModuleSVN              = kCatLoadedModule | 0x000B;
constexpr uint32_t SipaModuleOriginalFileName = kCatLoadedModule | 0x000D;
constexpr uint32_t SipaModuleVersion          = kCatLoadedModule | 0x000E;
constexpr uint32_t SipaQuote                  = kCatTrustPoint | 0x0001;
constexpr uint32_t SipaQuoteSignature         = kCatTrustPoint | 0x0002;
constexpr uint32_t SipaAIKID                  = kCatTrustPoint | 0x0003;
constexpr uint32_t SipaAIKPubDigest           = kCatTrustPoint | 0x0004;
constexpr uint32_t SipaELAMKeyname            = kCatELAM | 0x0001;
constexpr uint32_t SipaELAMConfiguration      = kCatELAM | 0x0002;
constexpr uint32_t SipaELAMPolicy             = kCatELAM | 0x0003;
constexpr uint32_t SipaELAMMeasured           = kCatELAM | 0x0004;
constexpr uint32_t SipaVBSVSMRequired         = kCatVBS | 0x0001;
constexpr uint32_t SipaVBSSecureBootRequired  = kCatVBS | 0x0002;
constexpr uint32_t SipaVBSIOMMURequired       = kCatVBS | 0x0003;
constexpr uint32_t SipaVBSNXRequired          = kCatVBS | 0x0004;
constexpr uint32_t SipaVBSMSRFilterRequired   = kCatVBS | 0x0005;
constexpr uint32_t SipaVBSMandatoryEnforce    = kCatVBS | 0x0006;
constexpr uint32_t SipaVBSHVCIPolicy          = kCatVBS | 0x0007;
constexpr uint32_t SipaVBSMSBootChainRequired = kCatVBS | 0x0008;
constexpr uint32_t SipaVBSDumpUsesAmbientKeys = kCatVBS | 0x0009;
constexpr uint32_t SipaVBSVSMNoSecretsEnforce = kCatVBS | 0x000A;
constexpr uint32_t SipaKSRSignature           = kCatKSR | 0x0001;
constexpr uint32_t SipaDRTMStateAuth          = kCatDRTM | 0x0001;
constexpr uint32_t SipaDRTMSMMLevel           = kCatDRTM | 0x0002;
constexpr uint32_t SipaDRTMAMDSMMHash         = kCatDRTM | 0x0003;
constexpr uint32_t SipaDRTMAMDSMMSignerKey    = kCatDRTM | 0x0004;

struct SipaIdName { uint32_t id; const char* name; };
const SipaIdName kSipaNames[] = {
    {SipaTrustBoundary, "TRUSTBOUNDARY"},
    {SipaELAMAggregation, "ELAMAGGREGATION"},
    {SipaLoadedModuleAggr, "LOADEDMODULEAGGREGATION"},
    {SipaTrustpointAggregation, "TRUSTPOINTAGGREGATION"},
    {SipaKSRAggregation, "KSRAGGREGATION"},
    {SipaKSRSignedMeasurement, "KSRSIGNEDMEASUREMENTAGGREGATION"},
    {SipaInformation, "INFORMATION"},
    {SipaBootCounter, "BOOTCOUNTER"},
    {SipaTransferControl, "TRANSFER_CONTROL"},
    {SipaApplicationReturn, "APPLICATION_RETURN"},
    {SipaBitlockerUnlock, "BITLOCKER_UNLOCK"},
    {SipaEventCounter, "EVENTCOUNTER"},
    {SipaCounterID, "COUNTERID"},
    {SipaMORBitNotCancelable, "MORBIT_NOT_CANCELABLE"},
    {SipaApplicationSVN, "APPLICATION_SVN"},
    {SipaSVNChainStatus, "SVN_CHAIN_STATUS"},
    {SipaMORBitAPIStatus, "MORBIT_API_STATUS"},
    {SipaBootDebugging, "BOOTDEBUGGING"},
    {SipaBootRevocationList, "BOOT_REVOCATION_LIST"},
    {SipaOSKernelDebug, "OSKERNELDEBUG"},
    {SipaCodeIntegrity, "CODEINTEGRITY"},
    {SipaTestSigning, "TESTSIGNING"},
    {SipaDEP, "DATAEXECUTIONPREVENTION"},
    {SipaSafeMode, "SAFEMODE"},
    {SipaWinPE, "WINPE"},
    {SipaPAE, "PHYSICALADDRESSEXTENSION"},
    {SipaOSDevice, "OSDEVICE"},
    {SipaSystemRoot, "SYSTEMROOT"},
    {SipaHypervisorLaunchType, "HYPERVISOR_LAUNCH_TYPE"},
    {SipaHypervisorPath, "HYPERVISOR_PATH"},
    {SipaHypervisorIOMMUPolicy, "HYPERVISOR_IOMMU_POLICY"},
    {SipaHypervisorDebug, "HYPERVISOR_DEBUG"},
    {SipaDriverLoadPolicy, "DRIVER_LOAD_POLICY"},
    {SipaSIPolicy, "SI_POLICY"},
    {SipaHypervisorMMIONXPolicy, "HYPERVISOR_MMIO_NX_POLICY"},
    {SipaHypervisorMSRFilter, "HYPERVISOR_MSR_FILTER_POLICY"},
    {SipaVSMLaunchType, "VSM_LAUNCH_TYPE"},
    {SipaOSRevocationList, "OS_REVOCATION_LIST"},
    {SipaSMTStatus, "SMT_STATUS"},
    {SipaVSMIDKInfo, "VSM_IDK_INFO"},
    {SipaFlightSigning, "FLIGHTSIGNING"},
    {SipaPagefileEncryption, "PAGEFILE_ENCRYPTION_ENABLED"},
    {SipaVSMIDKSInfo, "VSM_IDKS_INFO"},
    {SipaHibernationDisabled, "HIBERNATION_DISABLED"},
    {SipaDumpsDisabled, "DUMPS_DISABLED"},
    {SipaDumpEncryptionEnabled, "DUMP_ENCRYPTION_ENABLED"},
    {SipaDumpEncryptionKey, "DUMP_ENCRYPTION_KEY_DIGEST"},
    {SipaLSAISOConfig, "LSAISO_CONFIG"},
    {SipaSIPolicySigner, "SI_POLICY_SIGNER"},
    {SipaNoAuthority, "NOAUTHORITY"},
    {SipaAuthorityPubKey, "AUTHORITYPUBKEY"},
    {SipaFilePath, "FILEPATH"},
    {SipaImageSize, "IMAGESIZE"},
    {SipaHashAlgorithmID, "HASHALGORITHMID"},
    {SipaAuthenticodeHash, "AUTHENTICODEHASH"},
    {SipaAuthorityIssuer, "AUTHORITYISSUER"},
    {SipaAuthoritySerial, "AUTHORITYSERIAL"},
    {SipaImageBase, "IMAGEBASE"},
    {SipaAuthorityPublisher, "AUTHORITYPUBLISHER"},
    {SipaAuthoritySHA1Thumb, "AUTHORITYSHA1THUMBPRINT"},
    {SipaImageValidated, "IMAGEVALIDATED"},
    {SipaModuleSVN, "MODULESVN"},
    {SipaModuleOriginalFileName, "MODULEORIGINALFILENAME"},
    {SipaModuleVersion, "MODULEVERSION"},
    {SipaQuote, "QUOTE"},
    {SipaQuoteSignature, "QUOTESIGNATURE"},
    {SipaAIKID, "AIKID"},
    {SipaAIKPubDigest, "AIKPUBDIGEST"},
    {SipaELAMKeyname, "ELAM_KEYNAME"},
    {SipaELAMConfiguration, "ELAM_CONFIGURATION"},
    {SipaELAMPolicy, "ELAM_POLICY"},
    {SipaELAMMeasured, "ELAM_MEASURED"},
    {SipaVBSVSMRequired, "VSM_REQUIRED"},
    {SipaVBSSecureBootRequired, "SECUREBOOT_REQUIRED"},
    {SipaVBSIOMMURequired, "IOMMU_REQUIRED"},
    {SipaVBSNXRequired, "NX_REQUIRED"},
    {SipaVBSMSRFilterRequired, "MSR_FILTERING_REQUIRED"},
    {SipaVBSMandatoryEnforce, "MANDATORY_ENFORCEMENT"},
    {SipaVBSHVCIPolicy, "HVCI_POLICY"},
    {SipaVBSMSBootChainRequired, "MICROSOFT_BOOT_CHAIN_REQUIRED"},
    {SipaVBSDumpUsesAmbientKeys, "DUMP_USES_AMBIENT_KEYS"},
    {SipaVBSVSMNoSecretsEnforce, "VSM_NOSECRETS_ENFORCED"},
    {SipaKSRSignature, "KSR_SIGNATURE"},
    {SipaDRTMStateAuth, "DRTM_STATE_AUTH"},
    {SipaDRTMSMMLevel, "DRTM_SMM_LEVEL"},
    {SipaDRTMAMDSMMHash, "DRTM_AMD_SMM_HASH"},
    {SipaDRTMAMDSMMSignerKey, "DRTM_AMD_SMM_SIGNER_KEY"},
};

bool U32LE(const std::vector<uint8_t>& b, uint32_t& v) {
    if (b.size() != 4) return false;
    v = uint32_t(b[0]) | (uint32_t(b[1]) << 8) | (uint32_t(b[2]) << 16) | (uint32_t(b[3]) << 24);
    return true;
}
bool U64LE(const std::vector<uint8_t>& b, uint64_t& v) {
    if (b.size() != 8) return false;
    v = uint64_t(Reader::U32Low(b.data(), 0)) | (uint64_t(Reader::U32Low(b.data(), 4)) << 32);
    return true;
}

// BitLocker 解锁方式标志位翻译（fed into SipaBitlockerUnlock 的值）。
// bit0 缓存密钥 / bit1 媒体密钥 / bit2 TPM / bit4 PIN / bit5 USB / bit6 恢复密钥...
std::string BitlockerFlags(uint32_t v) {
    if (v == 0) return "无 (启动管理器未解锁)";
    static const struct { uint32_t bit; const char* name; } names[] = {
        {0x0001, "缓存密钥"}, {0x0002, "媒体密钥"}, {0x0004, "TPM"},
        {0x0010, "PIN"}, {0x0020, "外部密钥 (USB)"}, {0x0040, "恢复密钥"},
        {0x0080, "口令"}, {0x0100, "网络密钥 (NKP)"}, {0x0200, "认证"},
    };
    std::string out;
    for (auto& n : names) {
        if (v & n.bit) {
            if (!out.empty()) out += "+";
            out += n.name;
        }
    }
    return out.empty() ? "未知标志" : out;
}

// 在二进制数据里"捞"可打印的 UTF-16 字符串（≥6 个字符才算），
// 用在 SI_POLICY / 吊销列表这种结构不固定的类型上 —— 里面常夹着
// 一段段 UTF-16 文件名，把能认出来的都捞出来拼接展示。
std::string ExtractUTF16Strings(const std::vector<uint8_t>& b) {
    std::vector<std::string> out;
    std::vector<uint8_t> cur;
    auto flush = [&]() {
        if (cur.size() >= 12) { // >= 6 UTF-16 code units
            std::string s = UTF16ToUTF8(cur.data(), cur.size(), true);
            if (IsPrintable(s)) out.push_back(std::move(s));
        }
        cur.clear();
    };
    for (size_t i = 0; i + 1 < b.size(); i += 2) {
        uint16_t c = uint16_t(b[i]) | (uint16_t(b[i + 1]) << 8);
        if (c >= 0x20 && c < 0x7F) {
            cur.push_back(b[i]);
            cur.push_back(b[i + 1]);
        } else {
            flush();
        }
    }
    flush();
    if (out.size() > 6) out.resize(6);
    std::string joined;
    for (size_t i = 0; i < out.size(); i++) {
        if (i) joined += " | ";
        joined += out[i];
    }
    return joined;
}

// SIPAEVENT_SI_POLICY_PAYLOAD: PolicyVersion u64, PolicyNameLength u16,
// HashAlgID u16, DigestLength u32, PolicyName[], Digest[].
std::string FormatSIPolicy(const std::vector<uint8_t>& b) {
    if (b.size() < 16) return ShortHex(b);
    uint64_t ver = uint64_t(Reader::U32Low(b.data(), 0)) | (uint64_t(Reader::U32Low(b.data(), 4)) << 32);
    size_t nameLen = Reader::U32Low(b.data(), 8) & 0xFFFF;
    uint16_t alg = uint16_t(Reader::U32Low(b.data(), 10) & 0xFFFF);
    size_t digLen = Reader::U32Low(b.data(), 12);
    if (b.size() < 16 + nameLen + digLen) return ShortHex(b);
    std::string name = UTF16ToUTF8(b.data() + 16, nameLen, true);
    std::string dig = Hex(b.data() + 16 + nameLen, digLen);
    return Format("%s (version %u.%u.%u.%u, %s %s)", name.c_str(),
                  unsigned((ver >> 48) & 0xFFFF), unsigned((ver >> 32) & 0xFFFF),
                  unsigned((ver >> 16) & 0xFFFF), unsigned(ver & 0xFFFF),
                  AlgName(alg).c_str(), dig.c_str());
}

// ── FormatSipaValue：叶子节点值的"翻译机" ─────────────────────────────
// SIPA 叶子节点的 body 就是一小段字节，具体含义由 type 决定：
//   · 1 字节的开关型（TestSigning/SafeMode/CodeIntegrity...）→ "0 (no)"/"N (yes)"
//   · UTF-16 文本型（FilePath/SystemRoot/模块原名...）      → 直接转文字
//   · 哈希型（AuthenticodeHash/AIK 摘要...）                → hex
//   · u64 数值型（ImageBase/ImageSize/版本号...）           → 格式化数字
//   · 枚举型（DriverLoadPolicy/DEP/TransferControl...）     → 查表出名字
// 版本号这种是"4 个 u16 打包进一个 u64"：0x0001_0002_0003_0004 → 1.2.3.4。
// 没登记的 type 走文件尾部的启发式兜底：试 u32 → u64 → UTF-16 → hex。
std::string FormatSipaValue(uint32_t typ, const std::vector<uint8_t>& b) {
    switch (typ) {
    case SipaBootDebugging: case SipaOSKernelDebug: case SipaCodeIntegrity:
    case SipaTestSigning: case SipaSafeMode: case SipaWinPE: case SipaPAE:
    case SipaHypervisorDebug: case SipaFlightSigning: case SipaPagefileEncryption:
    case SipaHibernationDisabled: case SipaDumpsDisabled: case SipaDumpEncryptionEnabled:
    case SipaImageValidated: case SipaVBSVSMRequired: case SipaVBSSecureBootRequired:
    case SipaVBSIOMMURequired: case SipaVBSNXRequired: case SipaVBSMSRFilterRequired:
    case SipaVBSMandatoryEnforce: case SipaVBSMSBootChainRequired:
    case SipaVBSDumpUsesAmbientKeys: case SipaVBSVSMNoSecretsEnforce:
    case SipaMORBitNotCancelable: case SipaNoAuthority:
        if (b.size() == 1) {
            return b[0] == 0 ? "0 (no)" : Format("%u (yes)", unsigned(b[0]));
        }
        break;
    case SipaFilePath: case SipaSystemRoot: case SipaHypervisorPath:
    case SipaAuthorityIssuer: case SipaAuthorityPublisher:
    case SipaModuleOriginalFileName: case SipaELAMKeyname:
        return UTF16ToUTF8(b, true);
    case SipaAuthenticodeHash: case SipaAuthoritySHA1Thumb: case SipaAuthoritySerial:
    case SipaDumpEncryptionKey: case SipaAIKPubDigest: case SipaELAMMeasured:
    case SipaDRTMAMDSMMHash: case SipaQuoteSignature: case SipaKSRSignature:
        return Hex(b);
    case SipaImageBase: {
        uint64_t v;
        if (U64LE(b, v)) return Format("0x%llX", (unsigned long long)v);
        break;
    }
    case SipaImageSize: {
        uint64_t v;
        if (U64LE(b, v)) return Format("%llu bytes (%llu KB)", (unsigned long long)v, (unsigned long long)(v / 1024));
        break;
    }
    case SipaHashAlgorithmID: {
        uint32_t v;
        if (U32LE(b, v)) {
            const char* n = nullptr;
            switch (v) {
                case 0x8004: n = "SHA1"; break;
                case 0x800C: n = "SHA256"; break;
                case 0x800D: n = "SHA384"; break;
                case 0x800E: n = "SHA512"; break;
                case 0x8003: n = "MD5"; break;
            }
            return n ? Format("%s (0x%X)", n, v) : Format("0x%X", v);
        }
        break;
    }
    case SipaModuleVersion: {
        uint64_t v;
        if (U64LE(b, v))
            return Format("%u.%u.%u.%u", unsigned((v >> 48) & 0xFFFF), unsigned((v >> 32) & 0xFFFF),
                          unsigned((v >> 16) & 0xFFFF), unsigned(v & 0xFFFF));
        break;
    }
    case SipaBootCounter: case SipaEventCounter: {
        uint64_t v;
        if (U64LE(b, v)) return Format("%llu", (unsigned long long)v);
        break;
    }
    case SipaCounterID: {
        uint64_t v;
        if (U64LE(b, v)) return Format("0x%016llX", (unsigned long long)v);
        break;
    }
    case SipaTransferControl: {
        uint32_t v;
        if (U32LE(b, v)) {
            const char* n = nullptr;
            switch (v) {
                case 0: n = "无"; break;
                case 1: n = "OS 加载器 (winload)"; break;
                case 2: n = "休眠恢复 (winresume)"; break;
                case 3: n = "Microsoft 实用工具"; break;
                case 4: n = "非 Microsoft 应用"; break;
                case 5: n = "启动管理器 (安全启动)"; break;
            }
            return n ? Format("%u (%s)", v, n) : Format("%u", v);
        }
        break;
    }
    case SipaApplicationReturn: case SipaApplicationSVN: case SipaSVNChainStatus:
    case SipaMORBitAPIStatus: case SipaLSAISOConfig: case SipaSMTStatus:
    case SipaHypervisorIOMMUPolicy: case SipaHypervisorMMIONXPolicy:
    case SipaHypervisorMSRFilter: case SipaModuleSVN: case SipaVBSHVCIPolicy:
    case SipaDRTMSMMLevel: case SipaDRTMStateAuth: {
        uint32_t v32;
        if (U32LE(b, v32)) return Format("%u (0x%X)", v32, v32);
        uint64_t v64;
        if (U64LE(b, v64)) return Format("%llu (0x%llX)", (unsigned long long)v64, (unsigned long long)v64);
        break;
    }
    case SipaBitlockerUnlock: {
        uint32_t v;
        if (U32LE(b, v)) return Format("0x%X (%s)", v, BitlockerFlags(v).c_str());
        break;
    }
    case SipaOSDevice: {
        uint32_t v;
        if (U32LE(b, v)) {
            const char* n = nullptr;
            switch (v) {
                case 0x00000000: n = "未知"; break;
                case 0x00010001: n = "块设备 硬盘"; break;
                case 0x00010002: n = "块设备 可移动磁盘"; break;
                case 0x00010003: n = "块设备 光驱"; break;
                case 0x00010004: n = "块设备 分区"; break;
                case 0x00010005: n = "块设备 文件"; break;
                case 0x00010006: n = "块设备 内存盘"; break;
                case 0x00010007: n = "块设备 虚拟硬盘"; break;
                case 0x00020001: n = "串口"; break;
                case 0x00030001: n = "UDP"; break;
                case 0x00040001: n = "VMBus"; break;
                case 0x00050001: n = "复合设备"; break;
            }
            return n ? Format("0x%08X (%s)", v, n) : Format("0x%08X", v);
        }
        break;
    }
    case SipaHypervisorLaunchType: case SipaVSMLaunchType: {
        uint64_t v;
        if (U64LE(b, v)) {
            const char* n = nullptr;
            switch (v) {
                case 0: n = "Off"; break;
                case 1: n = "Auto"; break;
                case 2: n = "Always"; break;
            }
            return n ? Format("%llu (%s)", (unsigned long long)v, n) : Format("%llu", (unsigned long long)v);
        }
        break;
    }
    case SipaDEP: {
        uint64_t v;
        if (U64LE(b, v)) {
            const char* n = nullptr;
            switch (v) {
                case 0: n = "选择加入 (默认)"; break;
                case 1: n = "选择退出"; break;
                case 2: n = "始终开启"; break;
                case 3: n = "始终关闭"; break;
            }
            return n ? Format("%llu (%s)", (unsigned long long)v, n) : Format("%llu", (unsigned long long)v);
        }
        break;
    }
    case SipaDriverLoadPolicy: {
        uint32_t v;
        if (U32LE(b, v)) {
            const char* n = nullptr;
            switch (v) {
                case 1: n = "仅良好"; break;
                case 3: n = "良好和未知"; break;
                case 7: n = "良好、未知和严重级不良"; break;
                case 8: n = "所有驱动"; break;
            }
            return n ? Format("%u (%s)", v, n) : Format("%u", v);
        }
        break;
    }
    case SipaSIPolicy:
        return FormatSIPolicy(b);
    case SipaSIPolicySigner: case SipaELAMConfiguration: case SipaELAMPolicy:
    case SipaVSMIDKInfo: case SipaVSMIDKSInfo: case SipaBootRevocationList:
    case SipaOSRevocationList: {
        std::string s = ExtractUTF16Strings(b);
        if (!s.empty()) return Format("%zu bytes; strings: %s", b.size(), s.c_str());
        return Format("%zu bytes: %s", b.size(), ShortHex(b).c_str());
    }
    case SipaAuthorityPubKey:
        return DescribeSpki(b);
    default:
        break;
    }
    // Fallback heuristics for unknown value encodings.
    if (b.size() == 1) return Format("0x%02X", b[0]);
    uint32_t v32;
    if (U32LE(b, v32)) return Format("%u (0x%X)", v32, v32);
    uint64_t v64;
    if (U64LE(b, v64)) return Format("%llu (0x%llX)", (unsigned long long)v64, (unsigned long long)v64);
    if (b.size() % 2 == 0) {
        std::string s = UTF16ToUTF8(b, true);
        if (s.size() > 2 && IsPrintable(s) && s.size() * 2 >= b.size() - 2) return s;
    }
    return ShortHex(b);
}

std::string ChildValue(const SipaNode& n, uint32_t typ) {
    for (auto& c : n.children) {
        if (c.type == typ) return c.value;
    }
    return "";
}

// ── SummarizeContainer：给容器节点起一行"标题" ────────────────────────
// 容器本身没有值，得从子节点里挑重点拼一句话：
//   · 模块聚合容器 → 优先"模块原名 - 发布者"，没名字就退而求其次用
//     文件路径的文件名，再不行给 Authenticode 哈希前 16 位
//   · 信任边界容器 → "N 个元素，M 个模块"
//   · ELAM 容器   → ELAM 驱动的键名
std::string SummarizeContainer(uint32_t typ, const std::vector<SipaNode>& children) {
    SipaNode tmp;
    tmp.children = children;
    switch (typ) {
    case SipaLoadedModuleAggr: {
        std::string name = ChildValue(tmp, SipaModuleOriginalFileName);
        std::string path = ChildValue(tmp, SipaFilePath);
        if (name.empty()) {
            name = path;
            size_t i = name.find_last_of("\\/");
            if (i != std::string::npos) name = name.substr(i + 1);
        }
        std::string pub = ChildValue(tmp, SipaAuthorityPublisher);
        if (pub.empty()) pub = ChildValue(tmp, SipaAuthorityIssuer);
        if (name.empty()) {
            std::string h = ChildValue(tmp, SipaAuthenticodeHash);
            if (h.size() > 16) h = h.substr(0, 16) + "...";
            name = "哈希 " + h;
        }
        if (!pub.empty()) return name + " - " + pub;
        return name;
    }
    case SipaTrustBoundary: {
        size_t mods = 0;
        for (auto& c : children) {
            if (c.type == SipaLoadedModuleAggr) mods++;
        }
        return Format("%zu element(s), %zu module(s)", children.size(), mods);
    }
    case SipaELAMAggregation:
        return ChildValue(tmp, SipaELAMKeyname);
    default:
        return Format("%zu element(s)", children.size());
    }
}

// ── DecodeSipaInner：SIPA TLV 核心解码（递归）─────────────────────────
// 数据就是一串 TLV（见文件头 ASCII 图）：type 4B + size 4B + body。
//   · body 剩余字节不够 size → 数据被截断，之前已解析的照常返回
//   · type 带 kAggregation 标志 → 容器：递归解码 body（depth 上限 8 层，
//     防脏数据把自己递归爆栈），value 用 SummarizeContainer 概括
//   · 普通叶子 → FormatSipaValue 翻译，并按内容定 kind（UI 用来着色）
// 注意：函数开头 len-off < 8 时不解析，循环条件 `len - off >= 8` 保证
// 头 8 字节完整；尾部不满 8 字节的残余直接丢弃。
std::vector<SipaNode> DecodeSipaInner(const uint8_t* data, size_t len, int depth) {
    std::vector<SipaNode> nodes;
    if (depth > 8 || !data) return nodes;
    size_t off = 0;
    while (len - off >= 8) {
        uint32_t typ = Reader::U32Low(data, off);
        uint32_t size = Reader::U32Low(data, off + 4);
        if (len - off - 8 < size) return nodes; // truncated record
        const uint8_t* body = data + off + 8;
        SipaNode n;
        n.type = typ;
        n.name = SipaName(typ);
        n.category = SipaCategory(typ);
        n.size = size;
        n.raw.assign(body, body + size);
        if (typ & kAggregation) {
            n.children = DecodeSipaInner(body, size, depth + 1);
            n.value = SummarizeContainer(typ, n.children);
            n.kind = "container";
        } else {
            n.value = FormatSipaValue(typ, n.raw);
            // Kind: re-derive cheaply from the value branches above.
            switch (typ) {
                case SipaFilePath: case SipaSystemRoot: case SipaHypervisorPath:
                case SipaAuthorityIssuer: case SipaAuthorityPublisher:
                case SipaModuleOriginalFileName: case SipaELAMKeyname:
                    n.kind = "text"; break;
                case SipaAuthenticodeHash: case SipaAuthoritySHA1Thumb: case SipaAuthoritySerial:
                case SipaDumpEncryptionKey: case SipaAIKPubDigest: case SipaELAMMeasured:
                case SipaDRTMAMDSMMHash: case SipaQuoteSignature: case SipaKSRSignature:
                    n.kind = "hex"; break;
                default:
                    n.kind = "text"; break;
            }
        }
        nodes.push_back(std::move(n));
        off += 8 + size;
    }
    return nodes;
}

void WalkSipa(const std::vector<SipaNode>& nodes, const std::function<void(const SipaNode&)>& fn) {
    for (auto& n : nodes) {
        fn(n);
        if (!n.children.empty()) WalkSipa(n.children, fn);
    }
}

} // namespace

// type → 名字（查 kSipaNames 表；查不到给 "SIPA_0x........"）。
std::string SipaName(uint32_t t) {
    for (auto& k : kSipaNames) {
        if (k.id == t) return k.name;
    }
    return Format("SIPA_0x%08X", t);
}

// type → 分类名：截出 bit16~23 查分类表；带聚合标志就加 "AGGREGATION, " 前缀。
std::string SipaCategory(uint32_t t) {
    uint32_t cat = t & 0x00FF0000;
    const char* n = nullptr;
    switch (cat) {
        case kCatContainer:      n = "CONTAINER"; break;
        case kCatInformation:    n = "INFORMATION"; break;
        case kCatError:          n = "ERROR"; break;
        case kCatPreOSParameter: n = "PREOSPARAMETER"; break;
        case kCatOSParameter:    n = "OSPARAMETER"; break;
        case kCatAuthority:      n = "AUTHORITY"; break;
        case kCatLoadedModule:   n = "LOADEDMODULE"; break;
        case kCatTrustPoint:     n = "TRUSTPOINT"; break;
        case kCatELAM:           n = "ELAM"; break;
        case kCatVBS:            n = "VBS"; break;
        case kCatKSR:            n = "KSR"; break;
        case kCatDRTM:           n = "DRTM"; break;
    }
    std::string out = n ? n : Format("CAT_0x%04X", cat >> 16);
    if (t & kAggregation) out = "AGGREGATION, " + out;
    return out;
}

// 解析入口：DecodeSipaInner 的包装（从 depth 0 开始）。
std::vector<SipaNode> DecodeSipa(const uint8_t* data, size_t len) {
    return DecodeSipaInner(data, len, 0);
}

// ── SipaLooksValid：试探性解析的"验货"步骤 ────────────────────────────
// DecodeNoAction/DecodeEventTag 拿到一段不认识的字节时，会先盲试 SIPA
// 解析。怎么知道这段字节"真的是 SIPA"而不是巧合？两个条件：
//   1) consumed == total：所有 TLV 的 8+size 加起来必须正好用完整个数据
//      （真正的 SIPA 块不会有剩余/不够的字节）
//   2) known > 0：至少有一个 type 在已知表里
// 两条都满足才采信，否则当作普通字节展示。
bool SipaLooksValid(const std::vector<SipaNode>& nodes, size_t total) {
    size_t consumed = 0, known = 0;
    for (auto& n : nodes) {
        consumed += 8 + n.size;
        for (auto& k : kSipaNames) {
            if (k.id == n.type) { known++; break; }
        }
    }
    return consumed == total && known > 0;
}

// ── SipaSummary：把整棵 SIPA 树压成一行字（事件列表用）────────────────
// 顶层节点逐个转成一句话拼起来：
//   · 信任边界容器 → "信任边界: N 个启动授权密钥，M 个模块" + 附加信息
//     （传输控制/BitLocker 解锁方式/SystemRoot/ELAM）
//   · 授权公钥 / 无授权 / 模块容器 → 各自一句话
//   · 其他 → "名字: 值"
// 超过 220 字符截断 —— 它只是一行摘要，细节在展开树里看。
std::string SipaSummary(const std::vector<SipaNode>& nodes) {
    std::string s;
    auto append = [&](const std::string& part) {
        if (!s.empty()) s += "; ";
        s += part;
    };
    for (auto& n : nodes) {
        if (n.type == SipaTrustBoundary) {
            size_t mods = 0, auths = 0;
            std::vector<std::string> extra;
            for (auto& c : n.children) {
                if (c.type == SipaLoadedModuleAggr) mods++;
                else if (c.type == SipaAuthorityPubKey) auths++;
                else if (c.type == SipaTransferControl) {
                    size_t i = c.value.find('(');
                    if (i != std::string::npos) {
                        std::string v = c.value.substr(i + 1);
                        if (!v.empty() && v.back() == ')') v.pop_back();
                        extra.push_back("传输到 " + v);
                    }
                } else if (c.type == SipaBitlockerUnlock) {
                    size_t i = c.value.find('(');
                    if (i != std::string::npos) {
                        std::string v = c.value.substr(i);
                        if (!v.empty() && v.back() == ')') v.pop_back();
                        extra.push_back("BitLocker: " + v);
                    }
                } else if (c.type == SipaSystemRoot) {
                    extra.push_back("SystemRoot=" + c.value);
                } else if (c.type == SipaELAMAggregation) {
                    extra.push_back("ELAM: " + c.value);
                }
            }
            std::string part = Format("信任边界: %zu 个模块", mods);
            if (auths > 0) {
                part = Format("信任边界: %zu 个启动授权密钥", auths);
                if (mods > 0) part += Format("，%zu 个模块", mods);
            }
            for (size_t i = 0; i < extra.size(); i++) {
                part += (i ? "; " : "; ") + extra[i];
            }
            append(part);
        } else if (n.type == SipaAuthorityPubKey) {
            append("授权公钥: " + n.value);
        } else if (n.type == SipaNoAuthority) {
            append("无授权 (未签名)");
        } else if (n.type == SipaLoadedModuleAggr) {
            append("模块: " + n.value);
        } else {
            append(n.name + ": " + n.value);
        }
    }
    if (s.size() > 220) s = s.substr(0, 217) + "...";
    return s;
}

// ── CollectSipaFlags：从 SIPA 树里挖"安全相关信号" ────────────────────
// 深度遍历（WalkSipa）所有节点，凡是发现可疑/值得注意的配置就打标记，
// UI 用它给事件加角标提示，比如：
//   TESTSIGNING=1 → "test-signing"（测试签名开启，风险）
//   CODEINTEGRITY=0 → "code-integrity-off"（代码完整性关闭）
//   HypervisorLaunchType≠0 → "hypervisor-enabled"（VBS/HVCI 在跑）
//   BitLocker 解锁值≠0 → "bitlocker-unlocked"
// 这些标记最终进事件的 flags（见 tcg_log.cpp DecodeEventTag）。
std::vector<std::string> CollectSipaFlags(const std::vector<SipaNode>& nodes) {
    std::vector<std::string> flags;
    auto add = [&](const char* f) {
        for (auto& x : flags) {
            if (x == f) return;
        }
        flags.emplace_back(f);
    };
    WalkSipa(nodes, [&](const SipaNode& n) {
        bool yes = n.raw.size() == 1 && n.raw[0] != 0;
        switch (n.type) {
        case SipaBootDebugging:  if (yes) add("boot-debugging"); break;
        case SipaOSKernelDebug:  if (yes) add("kernel-debugging"); break;
        case SipaTestSigning:    if (yes) add("test-signing"); break;
        case SipaFlightSigning:  if (yes) add("flight-signing"); break;
        case SipaCodeIntegrity:  if (n.raw.size() == 1 && n.raw[0] == 0) add("code-integrity-off"); break;
        case SipaSafeMode:       if (yes) add("safe-mode"); break;
        case SipaWinPE:          if (yes) add("winpe"); break;
        case SipaHypervisorDebug: if (yes) add("hypervisor-debugging"); break;
        case SipaImageValidated: if (n.raw.size() == 1 && n.raw[0] == 0) add("module-not-validated"); break;
        case SipaNoAuthority:    add("no-authority"); break;
        case SipaELAMAggregation: add("elam"); break;
        case SipaVSMLaunchType: {
            uint64_t v;
            if (U64LE(n.raw, v) && v != 0) add("vbs-enabled");
            break;
        }
        case SipaHypervisorLaunchType: {
            uint64_t v;
            if (U64LE(n.raw, v) && v != 0) add("hypervisor-enabled");
            break;
        }
        case SipaBitlockerUnlock: {
            uint32_t v;
            if (U32LE(n.raw, v) && v != 0) add("bitlocker-unlocked");
            break;
        }
        default: break;
        }
    });
    return flags;
}

// 收集树里所有"加载模块聚合容器"节点（SipaModules 按字面意思），
// 模块详情页用这个列表逐个展示每个被度量加载的模块。
std::vector<const SipaNode*> SipaModules(const std::vector<SipaNode>& nodes) {
    std::vector<const SipaNode*> out;
    WalkSipa(nodes, [&](const SipaNode& n) {
        if (n.type == SipaLoadedModuleAggr) out.push_back(&n);
    });
    return out;
}

} // namespace tcg
