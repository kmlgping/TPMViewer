// ============================================================================
//  tbs_api.cpp —— 怎样和 TPM 芯片"通话"（学习注解版）
// ============================================================================
//
// 【这段代码干什么】
//   TPM（可信平台模块）是主板上一颗独立的安全芯片，里面有一堆 PCR 寄存器
//   和加密引擎。Windows 不允许程序直接摸硬件，必须经过系统层的 TBS
//   （TPM Base Services，一个随系统启动的中间服务）—— 它负责在多个进程
//   之间排队仲裁 TPM 的使用权，我们的程序只是它的一个"客户"。
//
//   我们 LoadLibrary("tbs.dll") 拿到 4 个入口：
//     Tbsi_Context_Create    → 开一个"会话"（类比 fopen）
//     Tbsip_Submit_Command   → 发一条 TPM 命令字节流，收回一段响应字节流
//     Tbsi_Get_TCG_Log       → 不用发命令，直接取固件写好的启动事件日志
//     Tbsip_Context_Close    → 关会话（析构函数里自动调用）
//
//   为什么动态加载而不是直接链接 tbs.lib？——程序要在没有 TPM 的机器上
//   也能启动（弹个"找不到 TPM"而不是直接崩）。
//
// 【TPM 2.0 命令的字节格式】（注意：全部大端 BE！x86 内存是小端，必须手工拼）
//
//   +--------+-----------+------------+--------+------------+
//   | tag    | paramSize | commandCode| handles| parameters |
//   |  2B    |    4B     |    4B      | 0~N B  |  剩余部分  |
//   +--------+-----------+------------+--------+------------+
//     tag        = 0x8001 (TPM_ST_NO_SESSIONS)，这条命令不带会话/加密
//     paramSize  = 整条命令总字节数
//     commandCode= 命令编号：PCR_Read = 0x17E，GetCapability = 0x17A
//
//   响应布局：
//   +--------+-----------+--------+---------------------------+
//   | tag    | paramSize |   rc   | handle/参数...            |
//   |  2B    |    4B     |   4B   |                           |
//   +--------+-----------+--------+---------------------------+
//     rc（返回码）在第 6 字节起，=0 成功。见 Submit() 里 BE32(resp.data()+6)。
//
// 【为什么手工拼字节而不用 TPM 命令库】
//   这里只用两种命令（PCR_Read / GetCapability），总共几十字节。手工拼
//   既能看清每个字段的含义，又不用拖一整个 TPM2 库 —— 对学习更友好。
//
// 【字段长度备忘】
//   PCR 索引 0~23，共 24 个 → 选择位图要 3 字节（24 bit），字段叫 sizeofSelect。
// ============================================================================
#include "tbs_api.hpp"

#include <windows.h>

#include <cstdarg>
#include <cstdio>

namespace tcg {

namespace {

constexpr uint32_t kTbsContextVersionTwo = 2;
constexpr uint32_t kTbsIncludeTPM12 = 2; // bit 1 of TBS_CONTEXT_PARAMS2
constexpr uint32_t kTbsIncludeTPM20 = 4;
constexpr uint32_t kTbsSuccess = 0;
constexpr uint32_t kTbsErrInsufficientBuffer = 0x80284005;
constexpr uint32_t kTbsCommandLocalityZero = 0;
constexpr uint32_t kTbsCommandPriorityNormal = 200;

// TPM 2.0 constants.
constexpr uint16_t kTpmStNoSessions = 0x8001;
constexpr uint32_t kTpmCCPCRRead = 0x0000017E;
constexpr uint32_t kTpmCCGetCap = 0x0000017A;
constexpr uint32_t kTpmCapPCRs = 0x00000005;
constexpr uint32_t kTpmCapTPMProperties = 0x00000006;
constexpr uint32_t kPtFixed = 0x100;

using CreateFn = uint32_t(WINAPI*)(const void* params, void** hContext);
using CloseFn = uint32_t(WINAPI*)(void* hContext);
using SubmitFn = uint32_t(WINAPI*)(void* hContext, uint32_t locality, uint32_t priority,
                                   const uint8_t* cmd, uint32_t cmdLen, uint8_t* resp,
                                   uint32_t* respLen);
using GetLogFn = uint32_t(WINAPI*)(void* hContext, uint8_t* buf, uint32_t* bufLen);
using DevInfoFn = uint32_t(WINAPI*)(uint32_t size, void* buffer);

struct TbsProcs {
    bool loaded = false;
    CreateFn create = nullptr;
    CloseFn closeFn = nullptr;
    SubmitFn submit = nullptr;
    GetLogFn getLog = nullptr;
    DevInfoFn devInfo = nullptr;
};

const TbsProcs* Tbs() {
    static const TbsProcs procs = [] {
        TbsProcs r;
        HMODULE m = LoadLibraryW(L"tbs.dll");
        if (!m) return r;
        auto get = [&](const char* name) {
            return reinterpret_cast<void*>(GetProcAddress(m, name));
        };
        r.create = reinterpret_cast<CreateFn>(get("Tbsi_Context_Create"));
        r.closeFn = reinterpret_cast<CloseFn>(get("Tbsip_Context_Close"));
        r.submit = reinterpret_cast<SubmitFn>(get("Tbsip_Submit_Command"));
        r.getLog = reinterpret_cast<GetLogFn>(get("Tbsi_Get_TCG_Log"));
        r.devInfo = reinterpret_cast<DevInfoFn>(get("Tbsi_GetDeviceInfo"));
        r.loaded = r.create && r.closeFn && r.submit && r.getLog && r.devInfo;
        return r;
    }();
    return &procs;
}

void SetTbsErr(std::string* err, const char* op, uint32_t code) {
    if (!err) return;
    char buf[160];
    std::snprintf(buf, sizeof(buf), "%s failed: TBS_RESULT 0x%08X (%s)", op, code,
                  TbsResultName(code).c_str());
    *err = buf;
}

void SetMsg(std::string* err, const char* fmt, ...) {
    if (!err) return;
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    *err = buf;
}

// --- big-endian helpers -----------------------------------------------------

void PutBE32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(static_cast<uint8_t>(x >> 24));
    v.push_back(static_cast<uint8_t>(x >> 16));
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x));
}

void PutBE16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x));
}

uint32_t BE32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

uint16_t BE16(const uint8_t* p) { return uint16_t((uint16_t(p[0]) << 8) | uint16_t(p[1])); }

// 拼一条 TPM 命令头：tag(2B, BE) + paramSize(4B, BE) + commandCode(4B, BE) + body。
// body 由调用方（ReadPCRs / ActiveBanks / FixedProperties）自己填。
std::vector<uint8_t> BuildHeader(uint32_t cc, const std::vector<uint8_t>& body) {
    std::vector<uint8_t> cmd;
    cmd.reserve(10 + body.size());
    PutBE16(cmd, kTpmStNoSessions);
    PutBE32(cmd, uint32_t(10 + body.size()));
    PutBE32(cmd, cc);
    cmd.insert(cmd.end(), body.begin(), body.end());
    return cmd;
}

// Printable 4-char string from a TPM property value (bytes are big-endian).
std::string PropStr(uint32_t v) {
    const uint8_t b[4] = {uint8_t(v >> 24), uint8_t(v >> 16), uint8_t(v >> 8), uint8_t(v)};
    std::string out;
    for (uint8_t ch : b)
        if (ch >= 0x20 && ch < 0x7F) out.push_back(char(ch));
    return out;
}

} // namespace

std::string TbsResultName(uint32_t code) {
    switch (code) {
        case 0x80284001: return "TBS_E_INTERNAL_ERROR";
        case 0x80284002: return "TBS_E_BAD_PARAMETER";
        case 0x80284003: return "TBS_E_INVALID_OUTPUT_POINTER";
        case 0x80284004: return "TBS_E_INVALID_CONTEXT";
        case 0x80284005: return "TBS_E_INSUFFICIENT_BUFFER";
        case 0x80284006: return "TBS_E_IOERROR";
        case 0x80284007: return "TBS_E_INVALID_CONTEXT_PARAM";
        case 0x80284008: return "TBS_E_SERVICE_NOT_RUNNING";
        case 0x80284009: return "TBS_E_TOO_MANY_TBS_CONTEXTS";
        case 0x8028400A: return "TBS_E_TOO_MANY_RESOURCES";
        case 0x8028400B: return "TBS_E_SERVICE_START_PENDING";
        case 0x8028400C: return "TBS_E_PPI_NOT_SUPPORTED";
        case 0x8028400D: return "TBS_E_COMMAND_CANCELED";
        case 0x8028400E: return "TBS_E_BUFFER_TOO_LARGE";
        case 0x8028400F: return "TBS_E_TPM_NOT_FOUND";
        case 0x80284010: return "TBS_E_SERVICE_DISABLED";
        case 0x80284011: return "TBS_E_NO_EVENT_LOG";
        case 0x80284012: return "TBS_E_ACCESS_DENIED";
        case 0x80284013: return "TBS_E_PROVISIONING_NOT_ALLOWED";
        case 0x80284014: return "TBS_E_PPI_FUNCTION_UNSUPPORTED";
        case 0x80284015: return "TBS_E_OWNERAUTH_NOT_FOUND";
        case 0x80284016: return "TBS_E_PROVISIONING_INCOMPLETE";
    }
    return "unknown";
}

bool TbsGetDeviceInfo(TbsDeviceInfo& out, std::string* err) {
    const TbsProcs* p = Tbs();
    if (!p->loaded) {
        SetMsg(err, "tbs.dll not available");
        return false;
    }
    uint32_t code = p->devInfo(sizeof(TbsDeviceInfo), &out);
    if (code != kTbsSuccess) {
        SetTbsErr(err, "Tbsi_GetDeviceInfo", code);
        return false;
    }
    return true;
}

TbsContext::~TbsContext() {
    if (h_) {
        Tbs()->closeFn(h_);
        h_ = nullptr;
    }
}

std::unique_ptr<TbsContext> TbsContext::Open(std::string* err) {
    const TbsProcs* p = Tbs();
    if (!p->loaded) {
        SetMsg(err, "tbs.dll not available");
        return nullptr;
    }
    const uint32_t params[2] = {kTbsContextVersionTwo, kTbsIncludeTPM12 | kTbsIncludeTPM20};
    void* h = nullptr;
    uint32_t code = p->create(params, &h);
    if (code != kTbsSuccess) {
        SetTbsErr(err, "Tbsi_Context_Create", code);
        return nullptr;
    }
    std::unique_ptr<TbsContext> ctx(new TbsContext());
    ctx->h_ = h;
    return ctx;
}

bool TbsContext::GetTCGLog(std::vector<uint8_t>& out, std::string* err) {
    const TbsProcs* p = Tbs();
    uint32_t size = 0;
    // ── 两段式取日志（Windows API 常见套路）──────────────────────────
    // 第一遍：buf=nullptr，只问"日志多大"。正常返回成功+size，但有些
    // TBS 版本返回 TBS_E_INSUFFICIENT_BUFFER（0x80284005），同样算数。
    // 第二遍：分配 size 字节再取。
    // 这个 size 就是固件在启动时攒下来的事件日志（几百 KB 很正常）。
    uint32_t code = p->getLog(h_, nullptr, &size);
    if (code != kTbsSuccess && code != kTbsErrInsufficientBuffer) {
        SetTbsErr(err, "Tbsi_Get_TCG_Log(size)", code);
        return false;
    }
    if (size == 0) {
        SetMsg(err, "Tbsi_Get_TCG_Log reported an empty log");
        return false;
    }
    out.assign(size, 0);
    code = p->getLog(h_, out.data(), &size);
    if (code != kTbsSuccess) {
        SetTbsErr(err, "Tbsi_Get_TCG_Log", code);
        return false;
    }
    out.resize(size);
    return true;
}

bool TbsContext::Submit(const uint8_t* cmd, size_t cmdLen, std::vector<uint8_t>& resp,
                        std::string* err) {
    const TbsProcs* p = Tbs();
    uint8_t buf[4096];
    uint32_t respLen = sizeof(buf);
    uint32_t code = p->submit(h_, kTbsCommandLocalityZero, kTbsCommandPriorityNormal, cmd,
                              uint32_t(cmdLen), buf, &respLen);
    if (code != kTbsSuccess) {
        SetTbsErr(err, "Tbsip_Submit_Command", code);
        return false;
    }
    if (respLen < 10) {
        SetMsg(err, "TPM response too short (%u bytes)", respLen);
        return false;
    }
    resp.assign(buf, buf + respLen);
    // 响应头布局：tag(2B) + paramSize(4B) + rc(4B)。rc 在 offset 6，0 = 成功。
    // 非 0 时把命令编号一起报出来，方便定位是哪条命令被 TPM 拒了。
    uint32_t rc = BE32(resp.data() + 6);
    if (rc != 0) {
        SetMsg(err, "TPM command 0x%X returned TPM_RC 0x%03X", BE32(cmd + 6), rc);
        return false;
    }
    return true;
}

bool TbsContext::ReadPCRs(uint16_t alg, std::map<int, std::vector<uint8_t>>& out,
                          std::string* err) {
    out.clear();
    // ── PCR_Read 命令（cc=0x17E）的参数体 ─────────────────────────────
    //   pcrSelectionInCount (4B BE) = 1        ← 就选一个"哈希 bank"
    //   └─ TPMS_PCR_SELECTION:
    //        hash         (2B BE) = alg       ← SHA1(0x04)/SHA256(0x0B)...
    //        sizeofSelect (1B)    = 3         ← 位图占 3 字节
    //        pcrSelect    (3B)                ← bit k = 想读 PCR k
    // 规范限制：一条 PCR_Read 最多返回 8 个 PCR 的摘要。
    // 所以把 24 个 PCR 分成 3 批（0..7 / 8..15 / 16..23），每批 8 个。
    // 位图手工构造：sel[i/8] |= 1 << (i%8) —— 小端 bit 序。
    for (int start = 0; start < 24; start += 8) {
        std::vector<uint8_t> body;
        body.reserve(16);
        PutBE32(body, 1); // count
        PutBE16(body, alg);
        body.push_back(3); // sizeofSelect
        uint8_t sel[3] = {0, 0, 0};
        for (int i = start; i < start + 8 && i < 24; i++) sel[i / 8] |= uint8_t(1 << (i % 8));
        body.insert(body.end(), sel, sel + 3);
        std::vector<uint8_t> cmd = BuildHeader(kTpmCCPCRRead, body);
        std::vector<uint8_t> resp;
        if (!Submit(cmd.data(), cmd.size(), resp, err)) return false;

        // ── PCR_Read 响应解析（跳过 10B 头之后）──────────────────────
        //   pcrUpdateCounter (4B)   ← PCR 更新计数器，这里没用
        //   pcrSelectionOutCount (4B)
        //   └─ N 个 {hash(2B), sizeofSelect(1B), 位图}  ← TPM 复述"我给了你哪些 PCR"
        //   digestCount (4B)
        //   └─ N 个 {size(2B), digest 数据}
        // 两个 N 一一对应：selection 里第 i 个命中的 PCR 编号 → digest 里第 i 个值。
        // 命中的 PCR 编号靠扫位图恢复：bits[b/8] & (1<<(b%8))。
        const uint8_t* p = resp.data() + 10;
        size_t n = resp.size() - 10;
        if (n < 8) {
            SetMsg(err, "PCR_Read: truncated response");
            return false;
        }
        p += 4; // pcrUpdateCounter
        n -= 4;
        uint32_t count = BE32(p);
        p += 4;
        n -= 4;
        std::vector<int> selected;
        for (uint32_t i = 0; i < count; i++) {
            if (n < 3) {
                SetMsg(err, "PCR_Read: truncated selection entry");
                return false;
            }
            int m = p[2];
            if (n < size_t(3 + m)) {
                SetMsg(err, "PCR_Read: truncated selection bitmap");
                return false;
            }
            const uint8_t* bits = p + 3;
            for (int b = 0; b < m * 8; b++)
                if (bits[b / 8] & (1 << (b % 8))) selected.push_back(b);
            p += 3 + m;
            n -= 3 + m;
        }
        if (n < 4) {
            SetMsg(err, "PCR_Read: truncated digests");
            return false;
        }
        uint32_t dcount = BE32(p);
        p += 4;
        n -= 4;
        for (uint32_t i = 0; i < dcount; i++) {
            if (n < 2) {
                SetMsg(err, "PCR_Read: truncated digest");
                return false;
            }
            int sz = BE16(p);
            p += 2;
            n -= 2;
            if (n < size_t(sz)) {
                SetMsg(err, "PCR_Read: truncated digest data");
                return false;
            }
            if (size_t(i) < selected.size())
                out[selected[i]] = std::vector<uint8_t>(p, p + sz);
            p += sz;
            n -= size_t(sz);
        }
    }
    return true;
}

// ── GetCapability 命令（cc=0x17A）问 TPM"你有哪些激活的哈希 bank"──────
// 参数体：capability(4B)=TPM_CAP_PCRS(5) + property(4B)=0 + propertyCount(4B)=1
// 响应（跳过 10B 头）：moreData(1B) + capability(4B) + count(4B) + TPML_PCR_SELECTION
//   每个 TPMS_PCR_SELECTION = { hash(2B), sizeofSelect(1B), 位图 }：
//   hash=0x000B（SHA256）且位图全 1 → 说明 SHA256 bank 的 24 个 PCR 全部激活。
//   日志里如果写了 SHA256 摘要而 TPM 这个 bank 没激活 → 造假/异常，比对会失败。
bool TbsContext::ActiveBanks(std::vector<TbsBank>& out, std::string* err) {
    out.clear();
    std::vector<uint8_t> body;
    body.reserve(12);
    PutBE32(body, kTpmCapPCRs);
    PutBE32(body, 0);
    PutBE32(body, 1);
    std::vector<uint8_t> cmd = BuildHeader(kTpmCCGetCap, body);
    std::vector<uint8_t> resp;
    if (!Submit(cmd.data(), cmd.size(), resp, err)) return false;

    const uint8_t* p = resp.data() + 10;
    size_t n = resp.size() - 10;
    if (n < 9) {
        SetMsg(err, "GetCapability(PCRS): truncated");
        return false;
    }
    p += 5; // moreData + capability
    n -= 5;
    uint32_t count = BE32(p);
    p += 4;
    n -= 4;
    for (uint32_t i = 0; i < count; i++) {
        if (n < 3) break;
        TbsBank b;
        b.alg = BE16(p);
        int m = p[2];
        if (n < size_t(3 + m)) break;
        const uint8_t* bits = p + 3;
        for (int k = 0; k < m * 8; k++)
            if (bits[k / 8] & (1 << (k % 8))) b.pcrs.push_back(k);
        p += 3 + m;
        n -= 3 + m;
        if (!b.pcrs.empty()) out.push_back(std::move(b));
    }
    return true;
}

// ── GetCapability(cap=TPM_CAP_TPM_PROPERTIES) 读 TPM 固定属性 ─────────
//   问的是 PT_FIXED 区（0x100 起）64 个属性，每个属性 8B：{id(4B), value(4B)}。
//   我们关心的几个：
//     0x100~0x102  规格版本（Family "2.0" / Level / Revision），按 4 字符串拼
//     0x105        厂商 ID（如 "INTC"/"NTCz"，4 字符）
//     0x106~0x109  厂商自定义字符串（拼 4 个 = 最多 16 字符）
//     0x10B/0x10C  固件版本 v1/v2，拼成 a.b.c.d
//   属性值是 4 个 ASCII 字符时按大端存 —— PropStr() 负责还原成字符串。
bool TbsContext::FixedProperties(TbsProperties& out, std::string* err) {
    std::vector<uint8_t> body;
    body.reserve(12);
    PutBE32(body, kTpmCapTPMProperties);
    PutBE32(body, kPtFixed);
    PutBE32(body, 0x40);
    std::vector<uint8_t> cmd = BuildHeader(kTpmCCGetCap, body);
    std::vector<uint8_t> resp;
    if (!Submit(cmd.data(), cmd.size(), resp, err)) return false;

    const uint8_t* p = resp.data() + 10;
    size_t n = resp.size() - 10;
    if (n < 9) {
        SetMsg(err, "GetCapability(PROPERTIES): truncated");
        return false;
    }
    p += 5; // moreData + capability
    n -= 5;
    uint32_t count = BE32(p);
    p += 4;
    n -= 4;
    for (uint32_t i = 0; i < count && n >= 8; i++) {
        uint32_t prop = BE32(p);
        uint32_t val = BE32(p + 4);
        out.raw[prop] = val;
        p += 8;
        n -= 8;
    }
    out.specFamily = PropStr(out.raw[0x100]);
    out.specLevel = out.raw[0x101];
    out.specRevision = out.raw[0x102];
    out.manufacturer = PropStr(out.raw[0x105]);
    out.vendorString = PropStr(out.raw[0x106]) + PropStr(out.raw[0x107]) +
                       PropStr(out.raw[0x108]) + PropStr(out.raw[0x109]);
    uint32_t fw1 = out.raw[0x10B];
    uint32_t fw2 = out.raw[0x10C];
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", fw1 >> 16, fw1 & 0xFFFF, fw2 >> 16, fw2 & 0xFFFF);
    out.firmwareVersion = buf;
    return true;
}

} // namespace tcg
