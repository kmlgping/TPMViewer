// ============================================================================
//  tcg_log.cpp —— 解析 TCG 启动事件日志（学习注解版）
// ============================================================================
//
// 【什么是 TCG 事件日志】
//   开机过程中，固件（UEFI/BIOS）每做一件"值得度量"的事——跑了某段代码、
//   加载了某个启动项、读了 SecureBoot 变量——就：
//     1) 把这件事的哈希"扩展"进 TPM 的某个 PCR（replay.cpp 里的公式）
//     2) 把这件事的原文（谁、干了啥、哈希是多少）追加到内存里的日志区
//   这份日志就是"度量启动的证据链"。Windows 的 tbs.dll 能整个取出来。
//
//   日志本身 TPM 管不着（只是普通内存），可以被改 —— 所以要拿日志重放出
//   的 PCR 理论值和 TPM 硬件里的实际值比对（replay.cpp + app.cpp），对上了
//   才说明日志可信。日志=证据，PCR=结论，两者互相印证。
//
// 【整个日志的布局】（字节序：小端 LE！注意和 TPM 命令的大端相反）
//
//   ▌第 1 条记录：固定为 v1 格式（TCG_PCClientPCREvent），内容是日志头
//   ┌────────┬────────┬───────────────┬────────┬────────────┐
//   │ pcrIdx │ evType │ SHA1 摘要 20B │ dataLen│ event data │
//   │   4B   │   4B   │      20B      │   4B   │  dataLen B │
//   └────────┴────────┴───────────────┴────────┴────────────┘
//   v1 格式的摘要没有算法字段（默认 SHA1）。
//   event data 以 "Spec ID Event03" 开头 → 这是日志声明头，结构（ParseSpecID03）：
//   ┌──────────────┬─────────────┬───────┬───────┬────────┬──────────┬───────────┐
//   │ Signature 16B│PlatformClass│ minor │ major │ errata │uintnSize │numOfAlgs  │
//   │ "Spec ID     │   4B        │  1B   │  1B   │   1B   │    1B    │   4B      │
//   │  Event03"+0  │             │       │       │        │          │           │
//   └──────────────┴─────────────┴───────┴───────┴────────┴──────────┴───────────┘
//   然后 numOfAlgs 个 {algId 2B, digestSize 2B}，最后 vendorInfoSize 1B + vendorInfo。
//   ★ numOfAlgs 告诉我们后续每条事件的摘要长度怎么算 —— 没它后面没法解析。
//
//   ▌之后每条记录：TCG_PCR_EVENT2（crypto-agile 格式，ParseEvent2）
//   ┌────────┬────────┬───────────┬────────────────────────┬────────┬────────────┐
//   │ pcrIdx │ evType │ digestCnt │ digest[{algId,dgst}]*N │ dataLen│ event data │
//   │   4B   │   4B   │    4B     │  每个摘要 = 2B + 长度   │   4B   │  dataLen B │
//   └────────┴────────┴───────────┴────────────────────────┴────────┴────────────┘
//   digest 的"长度"由日志头声明的算法表决定：SHA1=20、SHA256=32、SHA384=48。
//
// 【event data 里面是什么】—— 由 evType 决定，本文件每个 Decode 函数对应一种：
//   UEFI_VARIABLE* : GUID 16B + 名字长度 8B + 数据长度 8B + UTF16 名字 + 变量数据
//   镜像加载*      : 内存地址 8B + 长度 8B + 链接地址 8B + 设备路径长度 8B + 设备路径
//   GPT*           : "EFI PART" 签名 + GPT 头 + 分区表项
//   SEPARATOR      : 4 字节，0x00000000=正常收尾 / 0xFFFFFFFF=启动出错
//   NO_ACTION      : "Spec ID Event03"/"StartupLocality"/SIPA TLV...（不扩展 PCR）
//
// 【解析的容错哲学】
//   日志是固件手搓的，各种厂商实现质量参差。所以所有长度都先检查再读、
//   digest 数量/事件大小上限 16MB/16 个防脏数据、格式错了尽量展示已知部分。
// ============================================================================
// tcg_log.cpp — event log parsing + payload decoders (see tcg_log.hpp).
#include "tcg_log.hpp"
#include "util.hpp"
#include "hash.hpp"

#include <cctype>
#include <cstring>

namespace tcg {

// ---------------------------------------------------------------------------
// Event type names
// ---------------------------------------------------------------------------

std::string EventTypeName(uint32_t t) {
    switch (t) {
    case EvPrebootCert:                return "预启动证书";
    case EvPostCode:                   return "POST 代码";
    case EvUnused:                     return "未使用";
    case EvNoAction:                   return "无动作 (NO_ACTION)";
    case EvSeparator:                  return "分隔符 (SEPARATOR)";
    case EvAction:                     return "动作 (ACTION)";
    case EvEventTag:                   return "事件标签 (EVENT_TAG)";
    case EvSCRTMContents:              return "S-CRTM 内容";
    case EvSCRTMVersion:               return "S-CRTM 版本";
    case EvCPUMicrocode:               return "CPU 微码";
    case EvPlatformConfigFlags:        return "平台配置标志";
    case EvTableOfDevices:             return "设备表";
    case EvCompactHash:                return "紧凑哈希 (COMPACT_HASH)";
    case EvIPL:                        return "引导加载程序 (IPL)";
    case EvIPLPartitionData:           return "IPL 分区数据";
    case EvNonhostCode:                return "非宿主代码";
    case EvNonhostConfig:              return "非宿主配置";
    case EvNonhostInfo:                return "非宿主信息";
    case EvOmitBootDeviceEvts:         return "省略启动设备事件";
    case EvPostCode2:                  return "POST 代码 2";
    case EvEFIEventBase:               return "UEFI 事件基址";
    case EvEFIVariableDriverConfig:    return "UEFI 变量 (驱动配置)";
    case EvEFIVariableBoot:            return "UEFI 变量 (启动项)";
    case EvEFIBootServicesApplication: return "UEFI 启动服务应用";
    case EvEFIBootServicesDriver:      return "UEFI 启动服务驱动";
    case EvEFIRuntimeServicesDriver:   return "UEFI 运行时服务驱动";
    case EvEFIGPTEvent:                return "GPT 事件";
    case EvEFIAction:                  return "UEFI 动作";
    case EvEFIPlatformFirmwareBlob:    return "固件 Blob";
    case EvEFIHandoffTables:           return "交接表 (HANDOFF_TABLES)";
    case EvEFIPlatformFirmwareBlob2:   return "固件 Blob 2";
    case EvEFIHandoffTables2:          return "交接表 2";
    case EvEFIVariableBoot2:           return "UEFI 变量 (启动项 2)";
    case EvEFIGPTEvent2:               return "GPT 事件 2";
    case EvEFIHCRTMEvent:              return "H-CRTM 事件";
    case EvEFIVariableAuthority:       return "UEFI 变量 (授权)";
    case EvEFISPDMFirmwareBlob:        return "SPDM 固件 Blob";
    case EvEFISPDMFirmwareConfig:      return "SPDM 固件配置";
    case EvEFISPDMDevicePolicy:        return "SPDM 设备策略";
    case EvEFISPDMDeviceAuthority:     return "SPDM 设备授权";
    }
    return Format("未知 (0x%08X)", t);
}

// ---------------------------------------------------------------------------
// Small local helpers
// ---------------------------------------------------------------------------

namespace {

std::string AsStr(const uint8_t* b, size_t n) {
    return std::string(reinterpret_cast<const char*>(b), n);
}

// Trim trailing NULs (Go bytes.TrimRight(x, "\x00")).
std::string TrimNul(std::string s) {
    while (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

bool HasPrefix(const uint8_t* b, size_t n, const char* prefix) {
    size_t pl = strlen(prefix);
    return n >= pl && memcmp(b, prefix, pl) == 0;
}

uint16_t U16At(const uint8_t* b, size_t off) {
    return uint16_t(b[off]) | (uint16_t(b[off + 1]) << 8);
}
uint32_t U32At(const uint8_t* b, size_t off) {
    return Reader::U32Low(b, off);
}
uint64_t U64At(const uint8_t* b, size_t off) {
    return uint64_t(Reader::U32Low(b, off)) | (uint64_t(Reader::U32Low(b, off + 4)) << 32);
}

void SetField(Event& ev, const std::string& k, const std::string& v, const std::string& kind) {
    ev.fields.push_back(Field{k, v, kind});
}

std::string StrOf(const std::vector<uint8_t>& v) { return AsStr(v.data(), v.size()); }

std::string UpperCopy(std::string s) {
    for (auto& c : s) c = char(toupper((unsigned char)c));
    return s;
}

// ---------------------------------------------------------------------------
// UEFI variable / signature lists
// ---------------------------------------------------------------------------

} // namespace

// ── UEFI 变量事件的数据布局（EV_EFI_VARIABLE_* 事件通吃）──────────────
// UEFI_VARIABLE_DATA 结构：
//   ┌──────────────┬──────────────┬──────────────┐
//   │ VariableGUID │ UnicodeNameLen│ VariableDataLen │
//   │   16B        │    8B (u64)  │    8B (u64)   │
//   └──────────────┴──────────────┴──────────────┘
//   然后 UnicodeNameLen 个 UTF-16 字符（每个 2B）+ VariableDataLen 字节数据。
// GUID 标明变量归属（如 EFI_GLOBAL_VARIABLE=标准 UEFI 变量）。
// 名字常见的有：SecureBoot / PK / KEK / db / dbx / BootOrder / Boot0001...
// 解析成功后 out.name/out.data 指向日志内部（零拷贝），out.ok=true。
UefiVar ParseUefiVariable(const uint8_t* data, size_t len) {
    UefiVar out;
    if (len < 32) return out;
    out.guid = GUIDString(data);
    uint64_t nameLen = U64At(data, 16);
    uint64_t dataLen = U64At(data, 24);
    if (nameLen > 1024 || len < 32 + nameLen * 2 || len < 32 + nameLen * 2 + dataLen) {
        return out;
    }
    out.name = UTF16ToUTF8(data + 32, size_t(nameLen) * 2);
    out.data = data + 32 + nameLen * 2;
    out.dataLen = size_t(dataLen);
    out.ok = true;
    return out;
}

namespace {

// Tolerant X.509 summary; ok only when subject could be extracted.
bool TryCert(const uint8_t* der, size_t len, std::string& out) {
    std::string s = DescribeCert(der, len);
    if (s.empty() || s.rfind("X.509 (unparseable)", 0) == 0) return false;
    out = s;
    return true;
}

std::string DescribeSignature(const std::string& typ, const uint8_t* data, size_t len,
                              bool& isCert, std::string& subject) {
    isCert = false;
    subject.clear();
    std::string tn = GUIDName(typ);
    if (tn == "EFI_CERT_X509") {
        std::string s;
        if (TryCert(data, len, s)) {
            isCert = true;
            // 取 "主体 (签发者: X，有效期至 Y)" 的主体部分
            size_t k = s.find(" (签发者");
            subject = (k == std::string::npos) ? s : s.substr(0, k);
            return "X.509: " + s;
        }
        auto sum = Sha256(data, len);
        return Format("X.509 (无法解析), sha256=%s", Hex(sum).substr(0, 16).c_str());
    }
    if (tn == "EFI_CERT_SHA256" || tn == "EFI_CERT_SHA1" ||
        tn == "EFI_CERT_SHA384" || tn == "EFI_CERT_SHA512") {
        return Hex(data, len);
    }
    if (tn == "EFI_CERT_X509_SHA256" || tn == "EFI_CERT_X509_SHA384" ||
        tn == "EFI_CERT_X509_SHA512") {
        return "cert hash " + Hex(data, len);
    }
    if (len > 32) return Format("%d bytes", int(len));
    return Hex(data, len);
}

} // namespace

// ── EFI_SIGNATURE_LIST 解析（PK/KEK/db/dbx 的数据都是这个格式）─────────
// 一份签名库可以塞多条"签名列表"，每条列表：
//   ┌──────────────┬───────────┬──────────┬──────────┐
//   │ SignatureType│ ListSize  │ HeaderSize│ SignatureSize│
//   │  GUID 16B    │   4B      │    4B    │    4B    │
//   └──────────────┴───────────┴──────────┴──────────┘
//   + Header（HeaderSize 字节，通常为空）
//   + N 个签名条目，每个恰好 SignatureSize 字节：
//     ┌──────────────┬──────────────────────┐
//     │ Owner GUID   │ 证书/哈希数据        │
//     │   16B        │  SignatureSize-16B   │
//     └──────────────┴──────────────────────┘
// SignatureType 决定条目内容是什么：EFI_CERT_X509=证书、SHA256=裸哈希...
// dbx（吊销库）一般是 SHA256 哈希列表；db（允许库）一般是 X.509 证书。
std::vector<SigList> ParseSignatureLists(const uint8_t* data, size_t len, std::string& err) {
    std::vector<SigList> lists;
    size_t off = 0;
    while (len - off >= 28) {
        const uint8_t* p = data + off;
        size_t remaining = len - off;
        std::string typ = GUIDString(p);
        uint32_t listSize = U32At(p, 16);
        uint32_t hdrSize = U32At(p, 20);
        uint32_t sigSize = U32At(p, 24);
        if (listSize < 28 || remaining < listSize || sigSize < 16) {
            err = "malformed EFI_SIGNATURE_LIST";
            return lists;
        }
        SigList sl;
        sl.type = typ;
        size_t bodyOff = 28 + hdrSize;
        size_t bodyEnd = listSize;
        while (bodyEnd - bodyOff >= sigSize) {
            const uint8_t* e = p + bodyOff;
            SigEntry entry;
            entry.owner = GUIDString(e);
            entry.data.assign(e + 16, e + sigSize);
            entry.summary = DescribeSignature(typ, entry.data.data(), entry.data.size(),
                                              entry.isCert, entry.subject);
            sl.entries.push_back(std::move(entry));
            bodyOff += sigSize;
        }
        lists.push_back(std::move(sl));
        off += listSize;
    }
    return lists;
}

// ---------------------------------------------------------------------------
// Device path
// ---------------------------------------------------------------------------

namespace {

std::string EisaID(uint32_t id) {
    uint32_t v = id & 0xFFFF;
    char c1 = char(((v >> 10) & 0x1F) + '@');
    char c2 = char(((v >> 5) & 0x1F) + '@');
    char c3 = char((v & 0x1F) + '@');
    return Format("%c%c%c%04X", c1, c2, c3, id >> 16);
}

} // namespace

// ── UEFI 设备路径（Device Path）文本化 ─────────────────────────────────
// 设备路径是一串 TLV 节点：{Type 1B, SubType 1B, Length 2B}+数据，串到结尾
// 用 Type 0x7F/0xFF（End 节点）。Type 决定节点含义：
//   0x01 硬件（PCI 0x01）、0x02 ACPI（PciRoot 0x01）、0x03 消息
//        （SATA/NVMe/USB/MAC/IPv4...）、0x04 媒体（HD 分区 0x01/文件 0x04）
// 输出按 UEFI Shell 惯例拼成 "PciRoot(0x0)/Pci(0x1,0x0)/HD(1,GPT,...)"，
// 和 Windows bcdedit / UEFI 工具显示的一致，方便对照。
std::string DevicePath(const uint8_t* b, size_t len) {
    std::vector<std::string> parts;
    size_t off = 0;
    while (len - off >= 4) {
        const uint8_t* p = b + off;
        size_t remaining = len - off;
        uint8_t typ = p[0];
        uint8_t sub = p[1];
        uint16_t ln = U16At(p, 2);
        if (ln < 4 || ln > remaining) {
            parts.push_back("?(malformed)");
            break;
        }
        const uint8_t* d = p + 4;
        size_t dl = ln - 4;
        off += ln;
        switch (typ) {
        case 0x7F:
        case 0xFF:
            if (sub == 0x01) parts.push_back(",");
            continue;
        case 0x01: // hardware
            if (sub == 0x01 && dl >= 2) {
                parts.push_back(Format("Pci(0x%X,0x%X)", d[1], d[0]));
                continue;
            }
            if (sub == 0x03 && dl >= 20) {
                parts.push_back(Format("MemoryMapped(0x%X,0x%llX,0x%llX)",
                                       U32At(d, 0),
                                       (unsigned long long)U64At(d, 4),
                                       (unsigned long long)U64At(d, 12)));
                continue;
            }
            if (sub == 0x04 && dl >= 16) {
                parts.push_back(Format("VenHw(%s)", GUIDString(d).c_str()));
                continue;
            }
            parts.push_back(Format("HW(%d)", sub));
            break;
        case 0x02: // ACPI
            if (sub == 0x01 && dl >= 8) {
                uint32_t hid = U32At(d, 0);
                uint32_t uid = U32At(d, 4);
                if (hid == 0x0A0341D0) {
                    parts.push_back(Format("PciRoot(0x%X)", uid));
                } else if (hid == 0x0A0841D0) {
                    parts.push_back(Format("PcieRoot(0x%X)", uid));
                } else {
                    parts.push_back(Format("Acpi(%s,0x%X)", EisaID(hid).c_str(), uid));
                }
                continue;
            }
            parts.push_back(Format("Acpi(%d)", sub));
            break;
        case 0x03: // messaging
            if (sub == 0x01 && dl >= 4) {
                parts.push_back(Format("Ata(%d,%d,0x%X)", d[0], d[1], U16At(d, 2)));
                continue;
            }
            if (sub == 0x02 && dl >= 4) {
                parts.push_back(Format("Scsi(0x%X,0x%X)", U16At(d, 0), U16At(d, 2)));
                continue;
            }
            if (sub == 0x05 && dl >= 2) {
                parts.push_back(Format("USB(0x%X,0x%X)", d[0], d[1]));
                continue;
            }
            if (sub == 0x0B && dl >= 6) {
                parts.push_back(Format("MAC(%s)", Hex(d, 6).c_str()));
                continue;
            }
            if (sub == 0x0C) { parts.push_back("IPv4(...)"); continue; }
            if (sub == 0x0D) { parts.push_back("IPv6(...)"); continue; }
            if (sub == 0x12 && dl >= 6) {
                parts.push_back(Format("Sata(0x%X,0x%X,0x%X)",
                                       U16At(d, 0), U16At(d, 2), U16At(d, 4)));
                continue;
            }
            if (sub == 0x17 && dl >= 12) {
                parts.push_back(Format("NVMe(0x%X,%s)",
                                       U32At(d, 0), UpperCopy(Hex(d + 4, 8)).c_str()));
                continue;
            }
            if (sub == 0x18) {
                parts.push_back(Format("Uri(%s)", AsStr(d, dl).c_str()));
                continue;
            }
            if (sub == 0x1D && dl >= 1) {
                parts.push_back(Format("eMMC(0x%X)", d[0]));
                continue;
            }
            if (sub == 0x1A && dl >= 1) {
                parts.push_back(Format("SD(0x%X)", d[0]));
                continue;
            }
            parts.push_back(Format("Msg(%d)", sub));
            break;
        case 0x04: // media
            if (sub == 0x01 && dl >= 38) {
                uint32_t pn = U32At(d, 0);
                uint64_t start = U64At(d, 4);
                uint64_t size = U64At(d, 12);
                const uint8_t* sig = d + 20;
                uint8_t sigType = d[37];
                if (sigType == 2) {
                    parts.push_back(Format("HD(%d,GPT,%s,0x%llX,0x%llX)", pn,
                                           GUIDString(sig).c_str(),
                                           (unsigned long long)start,
                                           (unsigned long long)size));
                } else {
                    parts.push_back(Format("HD(%d,MBR,0x%08X,0x%llX,0x%llX)", pn,
                                           U32At(sig, 0),
                                           (unsigned long long)start,
                                           (unsigned long long)size));
                }
                continue;
            }
            if (sub == 0x02) { parts.push_back("CDROM(...)"); continue; }
            if (sub == 0x04) { parts.push_back(UTF16ToUTF8(d, dl)); continue; }
            if (sub == 0x06 && dl >= 16) {
                parts.push_back(Format("FvFile(%s)", GUIDString(d).c_str()));
                continue;
            }
            if (sub == 0x07 && dl >= 16) {
                parts.push_back(Format("Fv(%s)", GUIDString(d).c_str()));
                continue;
            }
            if (sub == 0x08 && dl >= 20) {
                parts.push_back(Format("Offset(0x%llX,0x%llX)",
                                       (unsigned long long)U64At(d, 4),
                                       (unsigned long long)U64At(d, 12)));
                continue;
            }
            if (sub == 0x09) { parts.push_back("RamDisk(...)"); continue; }
            parts.push_back(Format("Media(%d)", sub));
            break;
        case 0x05:
            parts.push_back("BBS(...)");
            break;
        default:
            parts.push_back(Format("Type%d(%d)", typ, sub));
            break;
        }
    }
    std::string s;
    for (size_t i = 0; i < parts.size(); i++) {
        if (i) s += "/";
        s += parts[i];
    }
    // Go: strings.ReplaceAll(s, "/,/", ",")
    size_t k;
    while ((k = s.find("/,/")) != std::string::npos) {
        s.replace(k, 3, ",");
    }
    return s;
}

// ---------------------------------------------------------------------------
// Event decoders
// ---------------------------------------------------------------------------

namespace {

// 分类：UI 分组用（secureboot/bootapp/config/action/windows/...）。
std::string CategoryFor(const Event& ev) {
    switch (ev.type) {
    case EvEventTag:
    case EvCompactHash:
        return "windows";
    case EvSeparator:
        return "separator";
    case EvEFIVariableDriverConfig:
    case EvEFIVariableAuthority:
        return "secureboot";
    case EvEFIBootServicesApplication:
        return "bootapp";
    case EvEFIBootServicesDriver:
    case EvEFIRuntimeServicesDriver:
        return "driver";
    case EvEFIVariableBoot:
    case EvEFIVariableBoot2:
    case EvEFIHandoffTables:
    case EvEFIHandoffTables2:
    case EvEFIGPTEvent:
    case EvEFIGPTEvent2:
        return "config";
    case EvEFIAction:
    case EvAction:
        return "action";
    }
    return "firmware";
}

// ── DecodeLoadOption：解析 BootXXXX 启动项变量（EFI_LOAD_OPTION 结构）──
// BootOrder 里的每个编号（如 0001）都对应一个名为 "Boot0001" 的变量，
// 它的数据就是 EFI_LOAD_OPTION：
//   ┌──────────┬──────────────────┬──────────────────────┬────────────────┬───────────┐
//   │ 属性 4B  │FilePathListLen 2B│ 描述（UTF-16，到      │ 设备路径       │ 可选数据  │
//   │          │                  │ 0x0000 为止）         │ (FPL 字节)     │ (剩余)    │
//   └──────────┴──────────────────┴──────────────────────┴────────────────┴───────────┘
//   attr 的 bit0=ACTIVE（启用才参与引导）、bit1=FORCE_RECONNECT、
//   bit3=HIDDEN、bit8~12=CATEGORY（0=启动应用 1=系统设置入口）。
//   "描述"就是 BIOS 启动菜单里看到的那行字（如 "Windows Boot Manager"），
//   "设备路径"指向要执行的 EFI 文件（如 \EFI\Microsoft\Boot\bootmgfw.efi）。
// 描述长度没法直接拿到，只能扫 UTF-16 找 0x0000 结尾 —— 所以要小心边界。
void DecodeLoadOption(Event& ev, const std::string& name, const uint8_t* vd, size_t n) {
    if (n < 6) {
        ev.summary = name;
        return;
    }
    uint32_t attr = U32At(vd, 0);
    int fpl = int(U16At(vd, 4));
    size_t pos = 6;
    // Description: NUL-terminated UTF-16.
    size_t descLen = 0;
    while (pos + descLen + 1 < n) {
        if (vd[pos + descLen] == 0 && vd[pos + descLen + 1] == 0) break;
        descLen += 2;
    }
    std::string desc = UTF16ToUTF8(vd + pos, descLen);
    size_t afterDesc = pos + (descLen + 2 <= n - pos ? descLen + 2 : n - pos);
    // rest = vd[afterDesc .. n)
    size_t restLen = n - afterDesc;
    const uint8_t* rest = vd + afterDesc;
    std::string dp;
    if (fpl >= 0 && size_t(fpl) <= restLen) {
        dp = DevicePath(rest, size_t(fpl));
        rest += fpl;
        restLen -= size_t(fpl);
    }
    SetField(ev, "描述", desc, "");
    std::string attrs = Format("0x%08X", attr);
    {
        std::vector<std::string> f;
        if (attr & 1) f.push_back("ACTIVE");
        if (attr & 2) f.push_back("FORCE_RECONNECT");
        if (attr & 8) f.push_back("HIDDEN");
        if (attr & 0x1F00) f.push_back(Format("CATEGORY_0x%X", (attr >> 8) & 0x1F));
        if (!f.empty()) {
            attrs += " (";
            for (size_t i = 0; i < f.size(); i++) {
                if (i) attrs += ", ";
                attrs += f[i];
            }
            attrs += ")";
        }
    }
    SetField(ev, "属性", attrs, "");
    SetField(ev, "设备路径", dp, "path");
    if (restLen > 0) {
        SetField(ev, "可选数据",
                 Format("%d 字节: %s", int(restLen), Hex(rest, restLen < 32 ? restLen : 32).c_str()),
                 "hex");
    }
    ev.summary = Format("%s: %s", name.c_str(), desc.c_str());
}

// ── DecodeVariableEvent：UEFI 变量事件的"分发中心" ────────────────────
// 先用 ParseUefiVariable 把 {GUID, 变量名, 数据} 拆出来，再按变量名决定
// 用什么方式展示 —— 变量数据的内容完全由变量名决定：
//   · SecureBoot / SetupMode / AuditMode / DeployedMode → 1 字节开关，直接显示
//   · PK / KEK / db / dbx / MokList...（签名库）        → ParseSignatureLists
//   · BootOrder                                          → 一串 u16 启动项编号
//   · Boot + 4 位十六进制（Boot0001 等）                → DecodeLoadOption
//   · 其他名字                                           → 尽力猜：
//     偶数长度且可打印 → 当 UTF-16 文本；≤8 字节 → 当整数；否则给字节数/hex
// 最后的兜底分支就是那个"尽力猜"，这也是 EV_EFI_VARIABLE_* 万能格式的代价。
void DecodeVariableEvent(Event& ev) {
    UefiVar v = ParseUefiVariable(ev.data.data(), ev.data.size());
    if (!v.ok) {
        ev.summary = "UEFI 变量数据格式错误";
        ev.flags.push_back("malformed");
        return;
    }
    SetField(ev, "变量", v.name, "");
    SetField(ev, "厂商 GUID", GUIDLabel(v.guid), "");
    SetField(ev, "数据长度", Format("%d 字节", int(v.dataLen)), "");
    const uint8_t* vd = v.data;
    size_t n = v.dataLen;
    const std::string& name = v.name;

    if (name == "SecureBoot" || name == "SetupMode" || name == "AuditMode" || name == "DeployedMode") {
        std::string val = "?";
        if (n >= 1) val = Format("%d", vd[0]);
        ev.summary = Format("%s = %s", name.c_str(), val.c_str());
        SetField(ev, "值", val, "bool");
        if (name == "SecureBoot" && n >= 1 && vd[0] == 0) ev.flags.push_back("secureboot-off");
        if (name == "SetupMode" && n >= 1 && vd[0] == 1) ev.flags.push_back("setup-mode");
        return;
    }

    bool sigDb = (name == "PK" || name == "KEK" || name == "db" || name == "dbx" ||
                  name == "dbt" || name == "dbr" || name == "MokList" ||
                  name == "MokListRT" || name == "MokListX");
    if (sigDb) {
        std::string err;
        auto lists = ParseSignatureLists(vd, n, err);
        int certs = 0, hashes = 0;
        std::string singleCert;
        for (size_t li = 0; li < lists.size(); li++) {
            auto& l = lists[li];
            std::string tn = GUIDName(l.type);
            if (tn.empty()) tn = l.type;
            for (size_t ei = 0; ei < l.entries.size(); ei++) {
                auto& e = l.entries[ei];
                std::string key = Format("[%d.%d] %s", int(li), int(ei), tn.c_str());
                if (e.isCert) {
                    certs++;
                    SetField(ev, key, e.summary, "cert");
                    if (singleCert.empty()) singleCert = e.subject;
                } else {
                    hashes++;
                    if (hashes <= 12) SetField(ev, key, e.summary, "hex");
                }
            }
        }
        if (hashes > 12) {
            SetField(ev, "…", Format("%d 个哈希条目未显示", hashes - 12), "");
        }
        if (!err.empty()) SetField(ev, "警告", err, "warn");
        if (n == 0) {
            ev.summary = Format("%s (空)", name.c_str());
            if (name == "PK" || name == "db") ev.flags.push_back("empty-" + name);
        } else {
            std::string parts;
            if (certs > 0) parts += Format("%d certificate(s)", certs);
            if (hashes > 0) {
                if (!parts.empty()) parts += ", ";
                parts += Format("%d hash(es)", hashes);
            }
            ev.summary = Format("%s: %s", name.c_str(), parts.c_str());
            if (certs == 1 && hashes == 0 && !singleCert.empty()) {
                ev.summary = Format("%s: %s", name.c_str(), singleCert.c_str());
            }
        }
        return;
    }

    if (name == "BootOrder") {
        std::string ids, order;
        for (size_t i = 0; i + 1 < n; i += 2) {
            if (!ids.empty()) ids += ", ";
            ids += Format("%04X", U16At(vd, i));
            if (!order.empty()) order += " \xE2\x86\x92 "; // "→"
            order += Format("%04X", U16At(vd, i));
        }
        ev.summary = "启动顺序 (BootOrder): " + ids;
        SetField(ev, "顺序", order, "");
        return;
    }

    if (name.size() == 8 && name.rfind("Boot", 0) == 0) {
        DecodeLoadOption(ev, name, vd, n);
        return;
    }

    if (ev.type == EvEFIVariableAuthority) {
        // EFI_SIGNATURE_DATA: owner GUID + certificate (or the whole cert).
        std::string summary;
        if (n > 16) {
            std::string s;
            if (TryCert(vd + 16, n - 16, s)) {
                summary = s.substr(0, s.find(" (签发者"));
                SetField(ev, "签名者 GUID", GUIDLabel(GUIDString(vd)), "");
                SetField(ev, "证书", s, "cert");
            } else if (TryCert(vd, n, s)) {
                summary = s.substr(0, s.find(" (签发者"));
                SetField(ev, "证书", s, "cert");
            }
        }
        if (summary.empty()) summary = Format("%d 字节", int(n));
        ev.summary = Format("%s 授权证书: %s", name.c_str(), summary.c_str());
        return;
    }

    std::string s = n % 2 == 0 ? UTF16ToUTF8(vd, n) : std::string();
    if (!s.empty() && IsPrintable(s) && s.size() > 1) {
        ev.summary = Format("%s = \"%s\"", name.c_str(), s.c_str());
    } else if (n <= 8 && n > 0) {
        ev.summary = Format("%s = 0x%s", name.c_str(), Hex(vd, n).c_str());
    } else {
        ev.summary = Format("%s (%d 字节)", name.c_str(), int(n));
    }
}

// ── DecodeImageLoad：镜像加载事件（UEFI_IMAGE_LOAD_EVENT）─────────────
// 固件每加载一个 EFI 程序/驱动就记一条。数据是固定 4 个 u64 + 设备路径：
//   ┌────────────┬────────────┬────────────┬──────────────┬────────────────┐
//   │ 加载地址 8B│ 长度 8B    │ 链接地址 8B│ 设备路径长 8B│ 设备路径 UTF-16│
//   │ ImageLoc   │ ImageLen   │ LinkAddr   │ DevPathLen   │ DevicePath     │
//   └────────────┴────────────┴────────────┴──────────────┴────────────────┘
// 加载地址/链接地址能看出镜像被放到了内存哪里；设备路径末段一般是
// 文件名（如 \EFI\Microsoft\Boot\bootmgfw.efi）。summary 只取文件名，
// 让 UI 列表更紧凑（末尾那个 rfind('/') + '\' 的判断就是干这个的）。
void DecodeImageLoad(Event& ev) {
    if (ev.data.size() < 32) {
        ev.summary = "UEFI 镜像加载事件格式错误";
        return;
    }
    const uint8_t* d = ev.data.data();
    uint64_t loc = U64At(d, 0);
    uint64_t ln = U64At(d, 8);
    uint64_t link = U64At(d, 16);
    uint64_t dpl = U64At(d, 24);
    std::string dp;
    if (ev.data.size() >= 32 + dpl) {
        dp = DevicePath(d + 32, size_t(dpl));
    }
    SetField(ev, "镜像内存地址", Format("0x%llX", (unsigned long long)loc), "");
    SetField(ev, "镜像内存长度",
             Format("0x%llX (%d KB)", (unsigned long long)ln, int(ln / 1024)), "");
    SetField(ev, "链接时地址", Format("0x%llX", (unsigned long long)link), "");
    SetField(ev, "设备路径", dp, "path");
    ev.summary = dp;
    // Go: last "/" with a "\" in the remainder -> keep file name part.
    size_t i = dp.rfind('/');
    if (i != std::string::npos && i + 1 < dp.size() && dp.find('\\', i + 1) != std::string::npos) {
        ev.summary = dp.substr(i + 1);
    }
    if (ev.summary.empty()) {
        ev.summary = Format("镜像 @0x%llX (%d KB)", (unsigned long long)loc, int(ln / 1024));
    }
}

// ── DecodeGPT：GPT 分区表事件（EV_EFI_GPT_EVENT，EFI_GPT_DATA 结构）───
// 固件读完磁盘分区表后，把"GPT 头 + 分区表"整块度量并原样拷进事件：
//   ┌──────────────────────────────────┬───────────────────────────────┐
//   │ GPT 头 92B（磁盘分区表的头，原样）│ TCG 附加字段 + 分区表项数组   │
//   │  offset 0 : "EFI PART" 签名 8B   │  offset 92 : 分区数 u64（TCG  │
//   │  offset 24: 当前 LBA u64         │   规格加的，标准 GPT 头没有） │
//   │  offset 56: 磁盘 GUID 16B        │  offset 100: 分区表项 × N     │
//   │  offset 84: 表项大小 u32         │   每项 128B（标准）：          │
//   └──────────────────────────────────┴───────────────────────────────┘
//     表项 = 类型GUID 16B（EFI 系统分区/微软保留...）+ 唯一GUID 16B
//          + 起始LBA 8B + 结束LBA 8B + 属性 8B + UTF-16 分区名 72B
// 注意区分两个 GUID：类型 GUID 说明"这是什么分区"，唯一 GUID 是这块盘上
// 这分区的身份证。LBA→MB 换算按 512 字节/扇区。
void DecodeGPT(Event& ev) {
    if (ev.data.size() < 92 + 8) {
        ev.summary = "GPT 数据格式错误";
        return;
    }
    const uint8_t* h = ev.data.data();
    if (memcmp(h, "EFI PART", 8) != 0) {
        ev.summary = "GPT 头签名缺失";
        ev.flags.push_back("malformed");
        return;
    }
    std::string diskGUID = GUIDString(h + 56);
    uint32_t entrySize = U32At(h, 84);
    uint64_t n = U64At(ev.data.data(), 92);
    SetField(ev, "磁盘 GUID", diskGUID, "");
    SetField(ev, "起始 LBA", Format("%llu", (unsigned long long)U64At(h, 24)), "");
    SetField(ev, "分区数", Format("%llu", (unsigned long long)n), "");
    const uint8_t* rest = ev.data.data() + 100;
    size_t restLen = ev.data.size() - 100;
    if (entrySize < 128) entrySize = 128;
    for (uint64_t i = 0; i < n && restLen >= entrySize; i++) {
        const uint8_t* e = rest;
        std::string typ = GUIDString(e);
        std::string uniq = GUIDString(e + 16);
        uint64_t start = U64At(e, 32);
        uint64_t end = U64At(e, 40);
        uint64_t attrs = U64At(e, 48);
        std::string pname = UTF16ToUTF8(e + 56, 72);
        std::string tn = GUIDName(typ);
        if (tn.empty()) tn = typ;
        uint64_t sizeMB = (end - start + 1) * 512 / (1024 * 1024);
        SetField(ev, Format("分区 %d", int(i + 1)),
                 Format("%s — %s — LBA %llu..%llu (%llu MB) attrs=0x%llX uid=%s",
                        pname.c_str(), tn.c_str(),
                        (unsigned long long)start, (unsigned long long)end,
                        (unsigned long long)sizeMB,
                        (unsigned long long)attrs, uniq.c_str()),
                 "");
        rest += entrySize;
        restLen -= entrySize;
    }
    ev.summary = Format("GPT 磁盘 %s，%d 个分区", diskGUID.c_str(), int(n));
}

// ── DecodeHandoffTables：交接表事件（固件把配置表交给 OS 前先度量）────
// ACPI、SMBIOS 这些表的内容太大，不会整个塞进事件，只记"哪张表、在哪"：
//   [v2 格式前缀: 描述长度 1B + 描述文本] + 表数量 u64 + N 个表项
//   每个表项 = 表的 GUID 16B + 表在内存里的地址 u64
// GUID 能认出是哪种表：ACPI 2.0 表 / ACPI 1.0 表 / SMBIOS 表。
// v1 格式（EvEFIHandoffTables）没有描述前缀，直接从表数量开始。
void DecodeHandoffTables(Event& ev) {
    const uint8_t* d = ev.data.data();
    size_t len = ev.data.size();
    std::string desc;
    if (ev.type == EvEFIHandoffTables2) {
        if (len < 1) return;
        size_t n = d[0];
        if (len < 1 + n) return;
        desc = AsStr(d + 1, n);
        d += 1 + n;
        len -= 1 + n;
        SetField(ev, "描述", desc, "");
    }
    if (len < 8) return;
    uint64_t count = U64At(d, 0);
    d += 8;
    len -= 8;
    std::string names;
    for (uint64_t i = 0; i < count && len >= 24; i++) {
        std::string g = GUIDString(d);
        uint64_t addr = U64At(d, 16);
        std::string gn = GUIDName(g);
        if (gn.empty()) gn = g;
        if (!names.empty()) names += ", ";
        names += gn;
        SetField(ev, Format("表 %d", int(i + 1)),
                 Format("%s @0x%llX", GUIDLabel(g).c_str(), (unsigned long long)addr), "");
        d += 24;
        len -= 24;
    }
    if (!desc.empty()) {
        ev.summary = Format("%s: %d 个表 (%s)", desc.c_str(), int(count), names.c_str());
    } else {
        ev.summary = Format("%d 个表: %s", int(count), names.c_str());
    }
}

// ── DecodeNoAction：NO_ACTION 事件（说明性内容，不参与 PCR 扩展）──────
// EV_NO_ACTION 的摘要在日志里是全 0（固件不真算哈希），data 是"说明书"，
// 不同固件往里塞不同东西。没有统一结构，只能按开头特征猜：
//   "StartupLocality"   → 1 字节 locality 值：TPM2_Startup 用哪个 locality
//                         启动的（0=普通，4=调试/特殊）。它会被写进 PCR0
//                         的末字节 —— replay.cpp 算 PCR0 初值时要用。
//   "Spec ID Event..."  → 日志声明头（就是第 1 条记录，见文件头 ASCII 图）
//   "SP800-155"         → NIST SP800-155 参考完整性清单指针
//   "H-CRTM"            → H-CRTM 度量结果说明
//   魔数 0xADF01995     → Windows Boot Manager 的 PCR 快照：bootmgr 把它
//                         眼中的 PCR0-7 值直接列出来，可以和重放结果对照
//                         格式：版本2B + 计数2B + 算法2B + 摘要长度2B + 摘要×N
//   SIPA TLV 结构       → 微软自己的度量数据（解码在 sipa.cpp）
//   都不是              → 当普通文本或字节数展示
void DecodeNoAction(Event& ev) {
    const uint8_t* d = ev.data.data();
    size_t len = ev.data.size();
    if (HasPrefix(d, len, "StartupLocality")) {
        uint8_t loc = 0;
        if (len >= 17) loc = d[16];
        ev.summary = Format("StartupLocality = %d", loc);
        SetField(ev, "StartupLocality", Format("%d", loc), "");
        return;
    }
    if (HasPrefix(d, len, "Spec ID Event")) {
        std::string s = AsStr(d, len < 16 ? len : 16);
        ev.summary = TrimNul(s);
        return;
    }
    if (HasPrefix(d, len, "SP800-155")) {
        ev.summary = "SP800-155 事件 (参考完整性清单指针)";
        return;
    }
    if (HasPrefix(d, len, "H-CRTM")) {
        ev.summary = "H-CRTM CompMeas";
        return;
    }
    if (len >= 14 && U32At(d, 0) == 0xADF01995) {
        // Windows Boot Manager PCR snapshot.
        int count = int(U16At(d, 8));
        uint16_t alg = U16At(d, 10);
        int size = int(U16At(d, 12));
        ev.summary = Format("启动管理器 PCR 快照: %d 个 PCR (%s)", count, AlgName(alg).c_str());
        ev.category = "windows";
        SetField(ev, "版本", Format("%d", U16At(d, 4)), "");
        SetField(ev, "算法", AlgName(alg), "");
        const uint8_t* p = d + 14;
        size_t pl = len - 14;
        for (int i = 0; i < count && pl >= size_t(size) && size > 0; i++) {
            SetField(ev, Format("PCR[%02d]", i), Hex(p, size_t(size)), "hex");
            p += size;
            pl -= size_t(size);
        }
        return;
    }
    // Microsoft's "SIPA" no-action events are TLV encoded too; try.
    auto nodes = DecodeSipa(d, len);
    if (!nodes.empty() && SipaLooksValid(nodes, len)) {
        ev.sipa = std::move(nodes);
        ev.summary = SipaSummary(ev.sipa);
        if (ev.summary.empty()) {
            ev.summary = Format("SIPA 数据 (%d 个元素)", int(ev.sipa.size()));
        }
        return;
    }
    std::string s = TrimNul(StrOf(ev.data));
    if (IsPrintable(s) && s.size() > 2) {
        ev.summary = s;
    } else {
        ev.summary = Format("%d 字节 (仅记录，不参与 PCR 扩展)", int(len));
    }
}

// ── DecodeEventTag：EVENT_TAG 事件（Windows 借它带 SIPA 数据）─────────
// EV_EVENT_TAG 本身只是个 u32 标签数字，但 Windows 的可信启动把它当
// 容器用，里面塞 SIPA TLV 结构（解析见 sipa.cpp）。所以这里先试 SIPA
// 解析；解析不出来就老实报告"N 字节"。
void DecodeEventTag(Event& ev) {
    auto nodes = DecodeSipa(ev.data.data(), ev.data.size());
    if (nodes.empty()) {
        ev.summary = Format("带标签事件，%d 字节", int(ev.data.size()));
        return;
    }
    ev.sipa = std::move(nodes);
    ev.summary = SipaSummary(ev.sipa);
    for (auto& f : CollectSipaFlags(ev.sipa)) ev.flags.push_back(std::move(f));
}

// ── DecodeEventInner：按事件类型分发的"总调度" ────────────────────────
// 每条事件解析完字节流后都走这里：
//   1) 先定分类（CategoryFor，UI 里按它着色/分组）
//   2) switch(ev.type) 分发到上面各个 Decode 函数
//   3) 没有专门解码器的类型走通用兜底：内容可打印就当文本，
//      POST 代码像 Blob 就按 {基地址,长度} 显示，否则 hex
// 无论哪个分支，summary 最后都不允许为空（UI 要显示一行字）。
void DecodeEventInner(Event& ev) {
    ev.category = CategoryFor(ev);
    switch (ev.type) {
    case EvEFIVariableDriverConfig:
    case EvEFIVariableBoot:
    case EvEFIVariableBoot2:
    case EvEFIVariableAuthority:
        DecodeVariableEvent(ev);
        break;
    case EvEFIBootServicesApplication:
    case EvEFIBootServicesDriver:
    case EvEFIRuntimeServicesDriver:
        DecodeImageLoad(ev);
        break;
    case EvEFIGPTEvent:
    case EvEFIGPTEvent2:
        DecodeGPT(ev);
        break;
    case EvEFIPlatformFirmwareBlob:
        if (ev.data.size() >= 16) {
            const uint8_t* d = ev.data.data();
            uint64_t base = U64At(d, 0);
            uint64_t ln = U64At(d, 8);
            SetField(ev, "BlobBase", Format("0x%llX", (unsigned long long)base), "");
            SetField(ev, "BlobLength",
                     Format("0x%llX (%d bytes)", (unsigned long long)ln, int(ln)), "");
            ev.summary = Format("固件 Blob @0x%llX (%d KB)",
                                (unsigned long long)base, int(ln / 1024));
        }
        break;
    case EvEFIPlatformFirmwareBlob2:
        if (ev.data.size() >= 1) {
            int n = ev.data[0];
            if (ev.data.size() >= size_t(1 + n + 16)) {
                const uint8_t* d = ev.data.data();
                std::string desc = AsStr(d + 1, size_t(n));
                uint64_t base = U64At(d, 1 + n);
                uint64_t ln = U64At(d, 9 + n);
                SetField(ev, "Description", desc, "");
                SetField(ev, "BlobBase", Format("0x%llX", (unsigned long long)base), "");
                SetField(ev, "BlobLength",
                         Format("0x%llX (%d KB)", (unsigned long long)ln, int(ln / 1024)), "");
                ev.summary = Format("%s @0x%llX (%d KB)", desc.c_str(),
                                    (unsigned long long)base, int(ln / 1024));
            }
        }
        break;
    case EvEFIHandoffTables:
    case EvEFIHandoffTables2:
        DecodeHandoffTables(ev);
        break;
    case EvEFIAction:
    case EvAction:
        ev.summary = TrimNul(StrOf(ev.data));
        SetField(ev, "Action", ev.summary, "");
        break;
    case EvSeparator: {
        if (ev.data.size() == 4) {
            uint32_t v = U32At(ev.data.data(), 0);
            if (v == 0) {
                ev.summary = "00000000 (正常)";
            } else if (v == 0xFFFFFFFF) {
                ev.summary = "FFFFFFFF (错误指示)";
                ev.flags.push_back("separator-error");
            } else if (memcmp(ev.data.data(), "WBCL", 4) == 0) {
                ev.summary = "WBCL (Windows 启动配置日志)";
            } else {
                ev.summary = Hex(ev.data);
            }
        } else {
            ev.summary = Hex(ev.data);
        }
        break;
    }
    case EvSCRTMVersion: {
        if (ev.data.size() == 16) {
            ev.summary = "GUID " + GUIDString(ev.data.data());
        } else {
            std::string s = UTF16ToUTF8(ev.data);
            if (IsPrintable(s) && s.size() > 1) {
                ev.summary = s;
            } else {
                ev.summary = Hex(ev.data);
            }
        }
        SetField(ev, "Version", ev.summary, "");
        break;
    }
    case EvCompactHash: {
        if (ev.data.size() == 4) {
            uint32_t v = U32At(ev.data.data(), 0);
            ev.summary = Format("数据 = 0x%08X", v);
            SetField(ev, "Data", Format("0x%08X", v), "");
        } else {
            ev.summary = Hex(ev.data);
        }
        break;
    }
    case EvNoAction:
        DecodeNoAction(ev);
        break;
    case EvEventTag:
        DecodeEventTag(ev);
        break;
    case EvPostCode:
    case EvPostCode2:
    case EvSCRTMContents: {
        std::string s = TrimNul(StrOf(ev.data));
        if (IsPrintable(s) && s.size() > 2) {
            ev.summary = s;
        } else if (ev.data.size() >= 16) {
            uint64_t base = U64At(ev.data.data(), 0);
            uint64_t ln = U64At(ev.data.data(), 8);
            ev.summary = Format("Blob @0x%llX (%d KB)", (unsigned long long)base, int(ln / 1024));
        }
        break;
    }
    default: {
        std::string s = TrimNul(StrOf(ev.data));
        if (IsPrintable(s) && s.size() > 2 && s.size() < 200) {
            ev.summary = s;
        } else {
            ev.summary = Format("%d bytes", int(ev.data.size()));
        }
        break;
    }
    }
    if (ev.summary.empty()) {
        ev.summary = Format("%d bytes", int(ev.data.size()));
    }
}

} // namespace

// ---------------------------------------------------------------------------
// Digest verification (hash of event data, where the spec defines it)
// ---------------------------------------------------------------------------

namespace {

// ── VerifyDigest：校验"日志里记的摘要" == "对 data 现算的哈希"？───────
// 这是发现"日志被篡改"的第一道检查：多数事件类型的摘要栏应该等于
// Hash(event data)。把两者一比，不一致就是日志有问题（或者固件实现烂）。
// 复杂点：不同事件类型对"哈希什么对象"的规定不一样：
//   · 大多数类型       → hash 整个 event data
//   · EFI_VARIABLE_BOOT/ AUTHORITY → 规格说只 hash 变量数据部分，
//     但有些固件偷懒 hash 整个结构 —— 所以准备 2 个候选都试，
//     哪个对上算哪个（digestHow 记录用的是哪种）
//   · 其余类型（PostCode 等） → 规格没定义哈希对象，跳过不比
// 逐个算法比：任何一个算法对不上就判失败；不支持的算法（如 SM3）跳过。
// 结果写入 ev.digestOK：+1 通过 / 0 无法判定 / -1 本应对上却没对上（可疑）。
// 第二个 switch 里列出的类型是"规格明确说该对上"的，失败才标 -1；
// 其他类型标 0，避免误报。真正的 PCR 一致性校验在 replay.cpp。
void VerifyDigest(Event& ev) {
    std::vector<std::pair<const uint8_t*, size_t>> candidates;
    switch (ev.type) {
    case EvEventTag:
    case EvSeparator:
    case EvEFIAction:
    case EvAction:
    case EvSCRTMVersion:
    case EvEFIVariableDriverConfig:
    case EvEFIGPTEvent:
    case EvEFIGPTEvent2:
    case EvEFIHandoffTables2:
    case EvEFIVariableBoot2:
    case EvPlatformConfigFlags:
    case EvTableOfDevices:
    case EvIPLPartitionData:
    case EvEFIHCRTMEvent:
    case EvNonhostConfig:
    case EvNonhostInfo:
        candidates.emplace_back(ev.data.data(), ev.data.size());
        break;
    case EvEFIVariableBoot:
    case EvEFIVariableAuthority: {
        // Spec says: hash of VariableData only for EV_EFI_VARIABLE_BOOT; some
        // firmware hashes the whole structure. Try both.
        UefiVar v = ParseUefiVariable(ev.data.data(), ev.data.size());
        if (v.ok) {
            candidates.emplace_back(v.data, v.dataLen);
            candidates.emplace_back(ev.data.data(), ev.data.size());
        } else {
            candidates.emplace_back(ev.data.data(), ev.data.size());
        }
        break;
    }
    default:
        return;
    }
    for (size_t ci = 0; ci < candidates.size(); ci++) {
        auto [cdata, clen] = candidates[ci];
        bool ok = true;
        bool checked = false;
        for (auto& d : ev.digests) {
            auto h = HashByAlg(d.alg, cdata, clen);
            if (h.empty()) continue; // unsupported algorithm (e.g. SM3)
            checked = true;
            if (h.size() != d.value.size() || memcmp(h.data(), d.value.data(), h.size()) != 0) {
                ok = false;
                break;
            }
        }
        if (checked && ok) {
            ev.digestOK = 1;
            ev.digestHow = (ci == 0 && candidates.size() > 1) ? "vardata" : "data";
            return;
        }
    }
    switch (ev.type) {
    case EvSeparator:
    case EvEventTag:
    case EvEFIAction:
    case EvEFIVariableDriverConfig:
    case EvEFIVariableBoot:
    case EvEFIVariableAuthority:
    case EvEFIGPTEvent:
        // Strong expectation: mismatch is suspicious.
        ev.digestOK = -1;
        break;
    }
}

} // namespace

// ---------------------------------------------------------------------------
// Parse
// ---------------------------------------------------------------------------

namespace {

// ── ParseSpecID03：解析日志声明头（第 1 条事件的 data 部分）───────────
// 字节布局见文件头 ASCII 图。核心产出是 s.algorithms 算法表 —— 它告诉
// 后面每条 TCG_PCR_EVENT2 里"每个摘要有多少字节"（SHA1=20/SHA256=32/...）。
// 没有这个表，digest 部分就没法定长切分，整个日志都读不下去。
// numOfAlgs > 16 视为脏数据直接拒绝 —— 正常最多 4~5 个算法。
bool ParseSpecID03(const uint8_t* data, size_t len, SpecInfo& s) {
    Reader r(data, len);
    const uint8_t* sig;
    if (!r.Bytes(16, &sig)) return false;
    s.signature = TrimNul(AsStr(sig, 16));
    uint32_t platformClass;
    uint8_t b[4];
    if (!r.U32(platformClass)) return false;
    s.platformClass = platformClass;
    if (!r.U8(b[0]) || !r.U8(b[1]) || !r.U8(b[2]) || !r.U8(b[3])) return false;
    s.minor = b[0];
    s.major = b[1];
    s.errata = b[2];
    s.uintnSize = b[3];
    uint32_t n;
    if (!r.U32(n)) return false;
    if (n > 16) return false;
    for (uint32_t i = 0; i < n; i++) {
        uint16_t alg, sz;
        if (!r.U16(alg) || !r.U16(sz)) return false;
        s.algorithms.push_back(AlgSize{alg, sz});
    }
    uint8_t vsz;
    if (!r.U8(vsz)) return false;
    const uint8_t* vi;
    if (r.Bytes(vsz, &vi)) s.vendorInfo.assign(vi, vi + vsz);
    return true;
}

// ── ParseEvent1：解析一条 v1 事件（老格式，只支持 SHA1）───────────────
//   ┌────────┬────────┬─────────────┬────────┬────────────┐
//   │ pcrIdx │ evType │ SHA1 摘要20B│ dataLen│ event data │
//   │   4B   │   4B   │     20B     │   4B   │  dataLen B │
//   └────────┴────────┴─────────────┴────────┴────────────┘
// dataLen 上限 16MB：正常事件最多几百字节，超限必是脏数据/错位，拒绝。
bool ParseEvent1(Reader& r, Event& ev) {
    if (!r.U32(ev.pcr)) return false;
    if (!r.U32(ev.type)) return false;
    const uint8_t* d;
    if (!r.Bytes(20, &d)) return false;
    ev.digests.push_back(Digest{AlgSha1, std::vector<uint8_t>(d, d + 20)});
    uint32_t size;
    if (!r.U32(size)) return false;
    if (size > 16u * 1024 * 1024) return false;
    const uint8_t* data;
    if (!r.Bytes(size, &data)) return false;
    ev.data.assign(data, data + size);
    return true;
}

// ── ParseEvent2：解析一条 crypto-agile 事件（TCG_PCR_EVENT2）──────────
//   ┌────────┬────────┬───────────┬──────────────────────┬────────┬────────────┐
//   │ pcrIdx │ evType │ digestCnt │ {algId 2B, 摘要 N B}×│ dataLen│ event data │
//   │   4B   │   4B   │    4B     │        cnt 个        │   4B   │  dataLen B │
//   └────────┴────────┴───────────┴──────────────────────┴────────┴────────────┘
// 关键：每个摘要的长度不是事件里自带的！要拿 algId 去查 Spec ID 声明的
// 算法表（ParseSpecID03 的产出）得到字节数；查不到再用内置默认表，
// 再查不到（未知算法）整个事件无法解析，只能放弃。
// digestCnt > 16 同样视为脏数据。
bool ParseEvent2(Reader& r, Event& ev, const SpecInfo& spec) {
    if (!r.U32(ev.pcr)) return false;
    if (!r.U32(ev.type)) return false;
    uint32_t count;
    if (!r.U32(count)) return false;
    if (count > 16) return false;
    for (uint32_t i = 0; i < count; i++) {
        uint16_t alg;
        if (!r.U16(alg)) return false;
        size_t sz = 0;
        for (auto& a : spec.algorithms) {
            if (a.alg == alg) sz = a.size;
        }
        if (sz == 0) sz = HashSizeByAlg(alg);
        if (sz == 0) return false;
        const uint8_t* d;
        if (!r.Bytes(sz, &d)) return false;
        ev.digests.push_back(Digest{alg, std::vector<uint8_t>(d, d + sz)});
    }
    uint32_t size;
    if (!r.U32(size)) return false;
    if (size > 16u * 1024 * 1024) return false;
    const uint8_t* data;
    if (!r.Bytes(size, &data)) return false;
    ev.data.assign(data, data + size);
    return true;
}

} // namespace

// ── Parse：日志解析总入口（raw = Tbsi_Get_TCG_Log 取回的整块日志）─────
// 流程分三步：
//   1) 第 1 条记录固定按 v1 老格式读（SHA1），看它的 data 是不是
//      "Spec ID Event03" 声明头：
//        是 → ParseSpecID03 解析算法表，之后所有事件按 v2 crypto-agile 读
//        否 → 这是 SHA1-only 老日志；第 1 条记录可能还是真事件，
//             把读指针退回 offset 0 让它按事件重新读一遍
//   2) 循环读剩余事件，每条：
//        ParseEvent1/2 切出 pcr/type/digests/data
//        → VerifyDigest 校验摘要（防篡改第一道检查）
//        → DecodeEventInner 解出人话（summary + fields）
//   3) 任何一条读坏（越界/尺寸离谱）就记 error 并停止 —— 日志是顺序
//      结构，一处错位后面全乱，继续读只会产生垃圾。
Log Parse(const std::vector<uint8_t>& raw) {
    Log lg;
    lg.raw = raw;
    if (raw.size() < 32) {
        lg.errors.push_back("日志过短，不是 TCG 事件日志");
        return lg;
    }
    Reader r(raw.data(), raw.size());

    // First event is always in the TCG_PCClientPCREvent (SHA1) format.
    uint32_t pcr, typ;
    const uint8_t* sha1Digest;
    uint32_t size;
    r.U32(pcr);            // header PCR index (ignored)
    r.U32(typ);
    r.Bytes(20, &sha1Digest);
    if (!r.U32(size)) {
        lg.errors.push_back("日志意外结束");
        return lg;
    }
    const uint8_t* hdata;
    if (!r.Bytes(size, &hdata)) {
        lg.errors.push_back(Format("header event: unexpected end of log (need %u bytes, have %d)",
                                   size, int(r.Remaining())));
        return lg;
    }

    if (typ == EvNoAction && size >= 15 && HasPrefix(hdata, size, "Spec ID Event03")) {
        if (!ParseSpecID03(hdata, size, lg.spec)) {
            lg.errors.push_back("Spec ID Event03: 事件意外结束");
            return lg;
        }
        lg.spec.cryptoAgile = true;
    } else {
        // Legacy SHA1-only log (Spec ID Event00 or no header at all).
        lg.spec.signature = "SHA1 log";
        lg.spec.algorithms.push_back(AlgSize{AlgSha1, 20});
        if (!(typ == EvNoAction && size >= 14 && HasPrefix(hdata, size, "Spec ID Event0"))) {
            // The very first record is a real event; rewind.
            r.off = 0;
        } else {
            lg.spec.signature = TrimNul(AsStr(hdata, size < 16 ? size : 16));
        }
    }

    int idx = 0;
    while (r.Remaining() > 0) {
        size_t start = r.off;
        Event ev;
        ev.index = idx;
        ev.offset = start;
        bool ok = lg.spec.cryptoAgile ? ParseEvent2(r, ev, lg.spec) : ParseEvent1(r, ev);
        if (!ok) {
            lg.errors.push_back(Format("event %d at offset 0x%X: unexpected end of log or "
                                       "unreasonable size/digest count",
                                       idx, unsigned(start)));
            break;
        }
        ev.length = r.off - start;
        VerifyDigest(ev);
        DecodeEventInner(ev);
        lg.events.push_back(std::move(ev));
        idx++;
    }
    return lg;
}

} // namespace tcg
