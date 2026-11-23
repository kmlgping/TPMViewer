// ============================================================================
//  replay.cpp —— PCR 重放 + 比对（学习注解版）★ 整个项目最核心的算法 ★
// ============================================================================
//
// 【PCR 是什么】
//   TPM 里有 24 个 PCR（Platform Configuration Register，平台配置寄存器），
//   每个 PCR 能装一个哈希值（SHA1 bank = 20 字节，SHA256 bank = 32 字节...）。
//   它的特殊之处：不能"写"，只能"扩展"（extend）——
//
//        PCR新 = Hash( PCR旧 || 事件摘要 )
//
//   旧值在前、新摘要在后，拼起来再哈希一次，结果存回去。
//   像区块链：每条新记录都"骑"在全部历史之上，改历史任何一条，
//   最终值就对不上。固件启动时每做一件事就扩展一次，链式记账。
//
// 【哪些事记到哪个 PCR】（TCG PC Client 规范的惯例，PCRName 表在 app.cpp）
//   PCR 0~6   固件/硬件：BIOS 代码、平台配置、OptionROM、GPT、启动管理器
//   PCR 7     安全启动策略：SecureBoot/PK/KEK/db/dbx 等 UEFI 变量
//   PCR 8~15  操作系统：winload、驱动、AppInfo...
//   PCR 17~22 DRTM/信任域专用（普通启动不用）
//   PCR 23    应用保留
//
// 【"重放"（replay）在干什么】—— 本文件的核心
//   1) 从日志头（Spec ID Event03）知道固件用了哪些哈希算法（bank）
//   2) 给每个 bank 的每个 PCR 赋"初始值"（见 InitialPCR）
//   3) 按日志顺序，一条条把事件摘要扩展进对应 PCR → 得到"理论值" expected
//   4) 同时用 tbs_api 真的去 TPM 读 PCR → 得到"实际值" actual
//   5) expected == actual → 日志完整、没被删改（TPM 里的哈希链和日志对上了）
//      expected != actual → 有事件被删/改/伪造（除非碰巧哈希碰撞，概率可忽略）
//
//   ★ 想伪造日志的人面临两难：改日志 → expected 变了 → 和 TPM 里的 actual
//     对不上；想改 PCR 实际值 → TPM 硬件保护，做不到。这就是度量启动的安全模型。
//
// 【初始值约定】（为什么 PCR17~22 是 0xFF？）
//   PCR 0~16、23：全 0x00 —— 上电清零，普通扩展从零开始。
//   PCR 17~22    ：全 0xFF —— DRTM（动态可信根）专用。0xFF...FF 是哨兵值，
//                  表示"动态启动还没发生过"。一旦发生会被 DRTM 模块清掉
//                  再扩展。本程序不动这些 PCR 的逻辑，只照规范初始化。
//
// 【StartupLocality —— PCR0 最后一个字节的玄机】
//   TPM 启动时要知道"谁唤醒了我"（locality）：
//     0 = 普通上电（主板 -> TPM Reset）
//     4 = H-CRTM（固件在 POST 早期直接发起度量，权限 locality 4）
//   这个信息在"第一次扩展 PCR0"之前就要定下来，没法用扩展传递，所以
//   固件把它写在 PCR0 初始值的最后一个字节：0x0000...0X。
//   日志里名为 "StartupLocality" 的 EV_NO_ACTION 事件会告诉我们这个值
//   （数据 = "StartupLocality" 15 字节 + 1 字节 locality 值，见 DecodeNoAction）。
//   如果日志里有 H-CRTM 事件，locality 必然是 4（见 Replay() 里的覆盖逻辑）。
//
// 【一个事件可能带多个摘要】
//   crypto-agile 日志里每条事件带 N 个 {算法, 摘要}（SHA1 和 SHA256 都记）。
//   重放时每个 bank 各自扩展各自的。某 bank 缺摘要记 missing[alg]，
//   Partial(alg) 会据此判定"该 bank 重放结果不可信"。
// ============================================================================
// replay.cpp — PCR replay + comparison (see replay.hpp).
#include "replay.hpp"
#include "util.hpp"
#include "hash.hpp"

#include <cstring>
#include <set>

namespace tcg {

// 单个 PCR 的"出厂初始值"。
//   index 0~16/23 → 全 0x00；index 17~22 → 全 0xFF（DRTM 未发生哨兵值，见文件头）。
//   startupLocality != 0 时，PCR0 的最后一个字节换成 locality 值（0/4）。
std::vector<uint8_t> InitialPCR(int index, size_t size, uint8_t startupLocality) {
    std::vector<uint8_t> v(size, 0);
    if (index >= 17 && index <= 22) {
        for (auto& b : v) b = 0xFF;
    }
    if (index == 0 && startupLocality != 0 && size > 0) {
        v[size - 1] = startupLocality;
    }
    return v;
}

ReplayResult Replay(Log& lg) {
    ReplayResult res;

    // 第 1 步：确定能重放哪些 bank。
    // 日志头声明了算法列表（SHA1/SHA256/SHA384/SM3...），但本机 CNG 哈希
    // API 不一定都支持（比如 SM3 国密就别想）。拿空输入探一下 HashByAlg，
    // 能算的 bank 才参与重放，算不了的直接放弃（Partial() 会标出来）。
    for (auto& a : lg.spec.algorithms) {
        // Only banks we can actually hash (SHA1/256/384/512; CNG has no SM3).
        auto probe = HashByAlg(a.alg, (const uint8_t*)"", 0);
        if (!probe.empty()) res.banks.push_back(a.alg);
    }

    // 第 2 步：找出 StartupLocality（必须在第一次扩展 PCR0 之前确定，见文件头）。
    // "StartupLocality" 事件数据：前 15 字节是字符串，第 16 字节（下标 15
    // 是字符串结尾，实际值在 data[16]）是 locality 数字。
    for (auto& ev : lg.events) {
        if (ev.type == EvNoAction && ev.data.size() >= 17 &&
            memcmp(ev.data.data(), "StartupLocality", 15) == 0) {
            res.startupLocality = ev.data[16];
            break;
        }
    }
    // An H-CRTM event means the TPM was started by the hardware CRTM at
    // locality 4: PCR 0 starts as 0..04 and the H-CRTM digest is extended
    // into it (TCG PC Client Platform Firmware Profile, EV_EFI_HCRTM_EVENT).
    for (auto& ev : lg.events) {
        if (ev.type == EvEFIHCRTMEvent) {
            res.hcrtm = true;
            res.startupLocality = 4;
            break;
        }
    }

    // 第 3 步：给每个 bank 建一个 24 长度的 PCR 数组，全部赋初始值。
    // state[算法ID][PCR编号] = 当前值（重放过程中的"理论值"）。
    std::map<uint16_t, std::vector<std::vector<uint8_t>>> state;
    for (uint16_t alg : res.banks) {
        size_t size = HashSizeByAlg(alg);
        std::vector<std::vector<uint8_t>> pcrs;
        pcrs.reserve(24);
        for (int i = 0; i < 24; i++) {
            pcrs.push_back(InitialPCR(i, size, res.startupLocality));
        }
        state[alg] = std::move(pcrs);
    }

    // 第 4 步：重放主循环 —— 按日志顺序逐条扩展。
    //   EvNoAction 事件（如 SpecID/StartupLocality/SIPA）不扩展 PCR，跳过。
    //   每条事件可能带多个算法的摘要：哪个 bank 有摘要就扩展哪个 bank；
    //   哪个 bank 缺摘要，missing[alg]++（影响 Partial() 判定）。
    for (auto& ev : lg.events) {
        if (ev.type == EvNoAction || ev.pcr >= 24) continue;
        res.eventCount[ev.pcr]++;
        res.measured++;
        ev.pcrAfter.clear();
        std::set<uint16_t> seen;
        for (auto& d : ev.digests) {
            auto it = state.find(d.alg);
            if (it == state.end()) continue;
            seen.insert(d.alg);
            auto& pcrs = it->second;
            // ★ 核心公式：PCR_new = Hash( PCR_old || digest )
            //   旧值 20/32/48 字节 + 摘要，拼成一块再哈希。
            std::vector<uint8_t> buf = pcrs[ev.pcr];
            buf.insert(buf.end(), d.value.begin(), d.value.end());
            auto h = HashByAlg(d.alg, buf.data(), buf.size());
            if (h.empty()) continue;
            pcrs[ev.pcr] = h;
            // 记下"这条事件扩展完之后的 PCR 值"——UI 详情页展示用。
            ev.pcrAfter.push_back(Digest{d.alg, h});
        }
        for (uint16_t alg : res.banks) {
            if (!seen.count(alg)) res.missing[alg]++;
        }
    }

    // 第 5 步：把"理论值"搬进结果。Compare() 拿它和 TPM 的 actual 逐个比对。
    res.expected = std::move(state);
    return res;
}

std::string PCRStatus::String() const {
    const char* st = "?";
    if (match == 1) st = "MATCH";
    else if (match == -1) st = "MISMATCH";
    return Format("PCR[%02d] %s expected=%s actual=%s", index, st,
                  Hex(expected).c_str(), Hex(actual).c_str());
}

// 逐 PCR 比对：expected（日志重放出来的）vs actual（TPM 硬件里的）。
//   match: 1=一致  -1=不一致  0=没法比（缺 expected 或缺 actual）
//   注意 Partial(alg) 为真时（该 bank 有缺失摘要）根本不给 expected，
//   防止拿残缺数据比出"假不一致"吓人。
std::vector<PCRStatus> Compare(const ReplayResult& r, uint16_t alg,
                               const std::map<int, std::vector<uint8_t>>& actual) {
    std::vector<PCRStatus> out;
    out.reserve(24);
    const std::vector<std::vector<uint8_t>>* exp = nullptr;
    auto it = r.expected.find(alg);
    if (it != r.expected.end() && !r.Partial(alg)) exp = &it->second;
    for (int i = 0; i < 24; i++) {
        PCRStatus s;
        s.index = i;
        s.alg = alg;
        s.events = r.eventCount[i];
        if (exp) s.expected = (*exp)[i];
        auto a = actual.find(i);
        if (a != actual.end()) {
            s.actual = a->second;
            if (exp) {
                s.match = (s.actual.size() == s.expected.size() &&
                           memcmp(s.actual.data(), s.expected.data(), s.expected.size()) == 0)
                              ? 1 : -1;
            }
        }
        out.push_back(std::move(s));
    }
    return out;
}

} // namespace tcg
