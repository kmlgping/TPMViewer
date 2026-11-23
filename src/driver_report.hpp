// driver_report.hpp — Windows 运行时证明报告（Runtime Attestation Report）。
//
// 背景：
//   * GetRuntimeAttestationReport() 是 Windows 11 25H2 (build 26200) 起才
//     由 kernel32.dll 导出的新 API。它让用户态进程向安全内核 (VTL1) 请求
//     一份由 VTL1 用 RSA-PSS/SHA-512 签名的"系统状态报告"。
//   * 我们只请求 RuntimeReportTypeDriver（已加载驱动列表）。这份列表由
//     安全内核维护 —— 即使 VTL0 的内核被 rootkit 改了内存枚举结果，
//     也伪造不了这份报告（VTL0 写不了 VTL1 的内存）。
//   * 前提条件：系统开了 VBS + HVCI。不满足时 API 返回失败，此时不显示
//     "驱动"标签页。
//
// 本文件不依赖新 SDK：运行时报告的结构在 SDK 10.0.29648 的 winnt.h 里
// 才有，本机 SDK 太旧 —— 结构体在 driver_report.cpp 里按官方布局复刻。
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace tcg {

// 解析后的一条驱动记录（报告里的 offset 都已转成实际数据）。
struct DriverEntryView {
    std::string internalName;   // PE 资源段 VERSIONINFO 的 InternalName（CHAR[32]，可能被截断）
    std::string oemName;        // 签名 OPUS 块里的 OEM 名；inbox 微软签名驱动为空
    uint16_t loadCount = 0;     // 该镜像被系统加载过的次数
    bool unloaded = false;      // 当前已卸载（条目仍保留在列表里）
    bool bootDriver = false;    // 启动阶段加载（false = 运行期加载；boot 驱动详情在 TCG 日志里）
    bool hotPatchable = false;  // 该镜像可作为 Hotpatch 目标加载
    std::string imageHashAlg;   // 镜像哈希算法名（如 "SHA-512"）
    std::string imageHash;      // 磁盘上镜像的哈希（hex）
    std::string certThumbAlg;   // 签名叶证书指纹的哈希算法名
    std::string certThumb;      // 签名叶证书 SHA-512 指纹（hex）
};

// 一次成功拉取的完整驱动报告。
struct DriverReportResult {
    std::vector<DriverEntryView> drivers;
    bool reportOverflowed = false;   // 安全内核记录数超限 —— 列表可能不完整
    bool partialReport = false;      // 报告只包含部分 NT 驱动
    bool includeBootDrivers = false; // 是否包含启动驱动（否则在 TCG 日志里）
    std::string nonceHex;            // 我们发送、报告回显的 nonce（防重放）
    std::string packageNote;         // 包结构校验备注（digest 比对结果等）
    size_t packageSize = 0;          // 整个报告包字节数
};

// 拉取并解析当前系统的 driver report。
// 返回 false 时 *err 说明原因：
//   - kernel32 没有该导出   → Windows 版本低于 25H2
//   - ERROR_INVALID_PARAMETER → API 在但条件不满足（未开 VBS/HVCI 等）
bool FetchDriverReport(DriverReportResult* out, std::string* err);

} // namespace tcg
