// app.cpp — ImGui UI for the TPM measured boot viewer (events, PCR replay,
// TPM info, raw log). Mirrors the feature set of the reference BootViewer UI.
#include "app.hpp"

#include <windows.h>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <commdlg.h>

#include "hash.hpp"
#include "util.hpp"

#include <chrono>
#include <ctime>
#include <fstream>
#include <set>

#include <imgui.h>

namespace tcg {

// Mono font used for hex/digest values (set by main.cpp after font setup).
ImFont* gMonoFont = nullptr;

namespace {

constexpr ImVec4 kGood = {0.40f, 0.85f, 0.50f, 1.0f};
constexpr ImVec4 kInfo = {0.55f, 0.75f, 1.00f, 1.0f};
constexpr ImVec4 kWarn = {1.00f, 0.80f, 0.30f, 1.0f};
constexpr ImVec4 kBad  = {1.00f, 0.45f, 0.45f, 1.0f};
constexpr ImVec4 kGrey = {0.55f, 0.57f, 0.60f, 1.0f};

std::string NowString() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_s(&tm, &t);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

// ---- 拷贝辅助：字节序列 → 文本 -----------------------------------------

// 逐字节 hex（"xx xx xx"）。
static std::string BytesHexSpaced(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(n * 3);
    for (size_t i = 0; i < n; i++) {
        if (i) out += ' ';
        out += d[p[i] >> 4];
        out += d[p[i] & 15];
    }
    return out;
}

// 连续 hex（"xxxxxxxx"）。
static std::string BytesHexCont(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; i++) {
        out += d[p[i] >> 4];
        out += d[p[i] & 15];
    }
    return out;
}

// 可打印 ASCII 视图（不可见字符 → '.'）。
static std::string BytesAscii(const uint8_t* p, size_t n) {
    std::string out;
    out.reserve(n);
    for (size_t i = 0; i < n; i++) {
        uint8_t c = p[i];
        out.push_back(c >= 0x20 && c <= 0x7E ? char(c) : '.');
    }
    return out;
}

// 表格单元格右键菜单：拷贝单元格 / 拷贝整行（Tab 分隔，粘进 Excel 自动分列）。
// 必须紧跟在单元格文本绘制之后调用（弹窗锚定到该文本）。
// 弹窗 ID = 调用方的行 PushID + colIdx，避免 ImGui ID 冲突。
// rowJoined 传空串则只显示"拷贝单元格"。
static void CellCopyMenu(const std::string& cell, const std::string& rowJoined, int colIdx,
                         const char* label = "拷贝单元格") {
    ImGui::PushID(colIdx);
    if (ImGui::BeginPopupContextItem("cellcopy")) {
        if (ImGui::MenuItem(label)) ImGui::SetClipboardText(cell.c_str());
        if (!rowJoined.empty() && ImGui::MenuItem("拷贝整行 (Tab 分隔)"))
            ImGui::SetClipboardText(rowJoined.c_str());
        ImGui::EndPopup();
    }
    ImGui::PopID();
}

const char* PCRName(int i) {
    static const char* names[] = {
        "固件 (SRTM，BIOS/UEFI)",    "平台配置",
        "Option ROM / UEFI 驱动",    "Option ROM 配置",
        "启动管理器 (IPL)",          "启动配置 / GPT",
        "厂商自定义",                "安全启动策略",
        "操作系统保留（Windows 未用）", "操作系统保留（Windows 未用）",
        "操作系统保留（Windows 未用）", "BitLocker（访问控制）",
        "Windows 数据事件",          "Windows 启动模块",
        "启动授权",                  "保留 / 操作系统",
        "调试",                      "DRTM (Intel TXT / AMD SKINIT)",
        "DRTM",                      "DRTM",
        "DRTM",                      "DRTM",
        "DRTM",                      "应用支持",
    };
    return i >= 0 && i <= 23 ? names[i] : "?";
}

// Internal category id -> Chinese display name.
const char* CategoryName(const std::string& c) {
    if (c == "windows")   return "Windows";
    if (c == "separator") return "分隔符";
    if (c == "secureboot") return "安全启动";
    if (c == "bootapp")   return "启动应用";
    if (c == "driver")    return "驱动";
    if (c == "config")    return "配置";
    if (c == "action")    return "动作";
    if (c == "firmware")  return "固件";
    return c.c_str();
}

// Internal flag id -> Chinese display name (ids must stay untranslated).
const char* FlagName(const std::string& f) {
    if (f == "secureboot-off")          return "安全启动已关闭";
    if (f == "setup-mode")              return "安全启动处于 Setup 模式（密钥未注册）";
    if (f == "empty-PK")                return "平台密钥 (PK) 为空";
    if (f == "empty-db")                return "签名数据库 (db) 为空";
    if (f == "test-signing")            return "已启用测试签名";
    if (f == "boot-debugging")          return "已启用启动调试";
    if (f == "kernel-debugging")        return "已启用内核调试";
    if (f == "hypervisor-debugging")    return "已启用虚拟机监控程序调试";
    if (f == "flight-signing")          return "已启用预览版 (Flight) 签名";
    if (f == "code-integrity-off")      return "代码完整性已关闭";
    if (f == "no-authority")            return "模块缺少签名授权";
    if (f == "module-not-validated")    return "模块未经代码完整性校验";
    if (f == "safe-mode")               return "本次为安全模式启动";
    if (f == "winpe")                   return "从 WinPE / 安装介质启动";
    if (f == "separator-error")         return "分隔符事件值异常";
    if (f == "malformed")               return "事件格式错误或被截断";
    if (f == "elam")                    return "启动早期加载了 ELAM 反恶意软件驱动";
    if (f == "vbs-enabled")             return "已启用基于虚拟化的安全 (VBS)";
    if (f == "hypervisor-enabled")      return "已启用虚拟机监控程序 (Hyper-V)";
    if (f == "bitlocker-unlocked")      return "启动过程中解锁了 BitLocker 卷";
    return f.c_str();
}

bool ContainsCI(const std::string& hay, const std::string& needle) {
    if (needle.empty()) return true;
    auto lower = [](std::string s) {
        for (auto& c : s) c = char(tolower(uint8_t(c)));
        return s;
    };
    return lower(hay).find(lower(needle)) != std::string::npos;
}

void MonoText(const std::string& s) {
    ImGui::PushFont(gMonoFont ? gMonoFont : ImGui::GetFont());
    ImGui::TextUnformatted(s.c_str());
    ImGui::PopFont();
}

// 等宽字体 + 自动换行（表格里放超长 hex 用；128 字符的 SHA-512 单行放不下）。
void MonoTextWrapped(const std::string& s) {
    ImGui::PushFont(gMonoFont ? gMonoFont : ImGui::GetFont());
    ImGui::TextWrapped("%s", s.c_str());
    ImGui::PopFont();
}

std::wstring FileDialog(bool save) {
    wchar_t buf[MAX_PATH] = L"";
    OPENFILENAMEW of{};
    of.lStructSize = sizeof(of);
    of.hwndOwner = GetActiveWindow();
    of.lpstrFilter = L"度量启动日志 (*.log;*.bin)\0*.log;*.bin\0所有文件 (*.*)\0*.*\0";
    of.lpstrFile = buf;
    of.nMaxFile = MAX_PATH;
    wchar_t dir[MAX_PATH] = L"";
    wchar_t sysroot[MAX_PATH] = L"";
    if (GetEnvironmentVariableW(L"SystemRoot", sysroot, MAX_PATH) == 0 || !sysroot[0])
        wcscpy_s(sysroot, L"C:\\Windows");
    _snwprintf_s(dir, MAX_PATH, _TRUNCATE, L"%s\\Logs\\MeasuredBoot", sysroot);
    of.lpstrInitialDir = dir;
    of.Flags = OFN_HIDEREADONLY | OFN_NOCHANGEDIR;
    if (save) {
        of.lpstrDefExt = L"log";
        of.Flags |= OFN_OVERWRITEPROMPT;
        if (!GetSaveFileNameW(&of)) return L"";
    } else {
        of.Flags |= OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
        if (!GetOpenFileNameW(&of)) return L"";
    }
    return buf;
}

} // namespace

App::App() = default;

bool App::LoadLive(std::string* err) {
    auto ctx = TbsContext::Open(err);
    if (!ctx) return false;

    auto s = std::make_unique<Snapshot>();
    s->fromFile = false;
    s->sourceName = "本次启动 (Tbsi_Get_TCG_Log)";
    s->loadedAt = NowString();

    if (!ctx->GetTCGLog(s->raw, err)) return false;

    s->devOK = TbsGetDeviceInfo(s->dev, &s->devErr);
    s->propsOK = ctx->FixedProperties(s->props, &s->propsErr);
    s->banksOK = ctx->ActiveBanks(s->tpmBanks, &s->banksErr);

    s->log = Parse(s->raw);
    s->replay = Replay(s->log);

    s->pcrReadOK = true;
    for (uint16_t alg : s->replay.banks) {
        std::string e2;
        std::map<int, std::vector<uint8_t>> m;
        if (ctx->ReadPCRs(alg, m, &e2)) {
            s->actual[alg] = std::move(m);
        } else {
            s->pcrReadOK = false;
            s->pcrReadErr = e2;
        }
    }

    BuildDisplay(*s);

    // 运行时证明驱动报告（GetRuntimeAttestationReport，Win11 25H2+ 且
    // 需 VBS/HVCI）。失败不阻塞主流程 —— 只是拉不到就不显示"驱动"标签页。
    s->driversOK = FetchDriverReport(&s->drivers, &s->driversErr);
    s->driverTabVisible = s->driversOK;

    snap_ = std::move(s);
    selected_ = -1;
    return true;
}

bool App::LoadFile(const std::wstring& path, std::string* err) {
    std::ifstream f(path.c_str(), std::ios::binary);
    if (!f) {
        if (err) *err = "无法打开文件";
        return false;
    }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    auto s = std::make_unique<Snapshot>();
    s->fromFile = true;
    s->filePath = path;
    s->sourceName = UTF16ToUTF8(reinterpret_cast<const uint8_t*>(path.data()),
                                path.size() * 2, false);
    s->loadedAt = NowString();
    s->raw = std::move(data);
    s->log = Parse(s->raw);
    s->replay = Replay(s->log);
    BuildDisplay(*s);
    snap_ = std::move(s);
    selected_ = -1;
    return true;
}

void App::BuildDisplay(Snapshot& s) {
    // Per-event display data.
    s.evDigests.resize(s.log.events.size());
    s.evPcrAfter.resize(s.log.events.size());
    for (auto& ev : s.log.events) {
        for (auto& d : ev.digests)
            s.evDigests[ev.index].push_back({AlgName(d.alg), Hex(d.value), ev.digestOK == 1});
        for (auto& d : ev.pcrAfter)
            s.evPcrAfter[ev.index].push_back({AlgName(d.alg), Hex(d.value), true});
    }

    // PCR banks.
    s.digestFailures = 0;
    int totalMatched = 0, totalCompared = 0;
    for (uint16_t alg : s.replay.banks) {
        DispBank b;
        b.alg = AlgName(alg);
        b.algId = alg;
        b.partial = s.replay.Partial(alg);
        auto it = s.replay.missing.find(alg);
        b.missing = it != s.replay.missing.end() ? it->second : 0;
        b.measured = s.replay.measured;
        auto act = s.actual.find(alg);
        for (auto& st : Compare(s.replay, alg, act != s.actual.end() ? act->second
                                                                    : std::map<int, std::vector<uint8_t>>{})) {
            DispPCRRow r;
            r.index = st.index;
            r.name = PCRName(st.index);
            r.expected = st.match != 0 ? Hex(st.expected) : "";
            if (b.partial) r.expected.clear();
            r.actual = !st.actual.empty() ? Hex(st.actual) : "";
            r.match = b.partial ? 0 : st.match;
            r.events = st.events;
            if (r.match == 1) b.matched++;
            if (r.match != 0) b.total++;
            b.rows.push_back(std::move(r));
        }
        totalMatched += b.matched;
        totalCompared += b.total;
        s.banks.push_back(std::move(b));
    }
    for (auto& ev : s.log.events)
        if (ev.digestOK == -1) s.digestFailures++;

    // Findings.
    auto add = [&](char sev, std::string text) { s.findings.push_back({sev, std::move(text)}); };
    if (s.fromFile) add('i', "日志来自文件，不与当前 TPM 的实时值比较。");
    if (totalCompared > 0 && totalMatched < totalCompared)
        add('b', Format("%d/%d 个 PCR 比对值与日志重放结果不一致。",
                        totalCompared - totalMatched, totalCompared));
    if (s.replay.hcrtm) add('i', "存在 H-CRTM 事件：固件在 locality 4 下对自身做了度量。");
    std::string partial, full;
    for (auto& b : s.banks) {
        if (b.partial)
            partial += (partial.empty() ? "" : ", ") + b.alg;
        else
            full += (full.empty() ? "" : ", ") + b.alg;
    }
    if (!partial.empty() && !full.empty())
        add('i', Format("哈希库 %s 是部分库：Windows 只往 %s 度量，因此 %s 列出但不参与比对。",
                        partial.c_str(), full.c_str(), full.c_str()));
    if (s.digestFailures > 0)
        add('b', Format("%d 个事件的摘要校验失败（数据被截断或格式错误）。", s.digestFailures));
    std::set<std::string> fs;
    for (auto& ev : s.log.events)
        for (auto& f : ev.flags) fs.insert(f);
    auto has = [&](const char* f) { return fs.count(f) > 0; };
    if (has("secureboot-off")) add('b', "安全启动 (Secure Boot) 已关闭。");
    if (has("setup-mode")) add('i', "安全启动处于 Setup 模式（尚未注册密钥）。");
    if (has("empty-PK") || has("empty-db")) add('i', "安全启动密钥数据库中没有任何证书。");
    if (has("test-signing")) add('w', "已启用测试签名。");
    if (has("boot-debugging") || has("kernel-debugging") || has("hypervisor-debugging"))
        add('w', "启动配置中启用了内核/启动调试。");
    if (has("flight-signing")) add('w', "已启用预览版 (Flight) 签名。");
    if (has("code-integrity-off")) add('w', "代码完整性 (Code Integrity) 已关闭。");
    if (has("no-authority")) add('w', "部分已加载模块没有记录签名授权。");
    if (has("module-not-validated")) add('w', "部分模块未通过代码完整性校验。");
    if (has("safe-mode")) add('i', "本次以安全模式启动。");
    if (has("winpe")) add('i', "从 WinPE / 安装介质启动。");
    if (has("separator-error")) add('b', "某个分隔符事件的值不符合标准。");
    if (has("malformed")) add('w', "一个或多个事件格式错误或被截断。");
    if (has("elam")) add('g', "启动过程中运行了 ELAM（启动早期反恶意软件）驱动。");
    if (has("vbs-enabled")) add('g', "已启用基于虚拟化的安全 (VBS)。");
    if (has("bitlocker-unlocked")) add('g', "启动过程中解锁了 BitLocker 卷。");
    if (s.replay.eventCount[17] == 0 && !s.fromFile)
        add('i', "没有 DRTM 事件：本次启动未使用 PCR 17。");
    bool noteworthy = false;
    for (auto& f : s.findings)
        if (f.sev == 'w' || f.sev == 'b') noteworthy = true;
    if (!noteworthy && !s.fromFile)
        s.findings.insert(s.findings.begin(),
                          {'g', "未发现异常。"});

    // Verdict.
    s.verdictMatched = totalMatched;
    s.verdictTotal = totalCompared;
    if (s.fromFile) {
        s.verdictStatus = "file";
        s.verdictText = "已加载归档日志；数值不与 TPM 实时值比较。";
    } else if (!s.devOK || totalCompared == 0) {
        s.verdictStatus = "notpm";
        s.verdictText = "没有可用的 TPM 2.0 数据；无法进行 PCR 比对。";
    } else if (totalMatched == totalCompared && s.digestFailures == 0 && !noteworthy) {
        s.verdictStatus = "verified";
        s.verdictText = "度量启动验证通过：所有比对的 PCR 值都与日志重放结果一致。";
    } else if (totalMatched == totalCompared && s.digestFailures == 0) {
        s.verdictStatus = "attention";
        s.verdictText = "PCR 值与日志一致，但日志中存在值得注意的情况。";
    } else if (totalMatched == totalCompared) {
        s.verdictStatus = "mismatch";
        s.verdictText = Format("%d 个事件摘要校验失败。", s.digestFailures);
    } else {
        s.verdictStatus = "mismatch";
        s.verdictText = Format("%d 个 PCR 值与日志重放结果不一致。",
                               totalCompared - totalMatched);
    }
}

// ---- drawing ----------------------------------------------------------------

void App::Draw() {
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
    ImGuiWindowFlags wf = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                          ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus;
    ImGui::Begin("##main", nullptr, wf);

    if (!snap_) {
        ImGui::Dummy(ImVec2(0, 12));
        ImGui::TextUnformatted("TPM 度量启动查看器");
        ImGui::TextDisabled("解析本次启动的 TCG 事件日志，重放 PCR 值并与 TPM 中的真实值比对。");
        ImGui::Dummy(ImVec2(0, 12));
        if (ImGui::Button("读取本次启动日志 (TPM)", ImVec2(240, 30))) {
            std::string e;
            if (!LoadLive(&e)) lastError_ = e;
        }
        ImGui::SameLine();
        if (ImGui::Button("打开日志文件...", ImVec2(180, 30))) {
            std::wstring p = FileDialog(false);
            if (!p.empty()) {
                std::string e;
                if (!LoadFile(p, &e)) lastError_ = e;
            }
        }
        if (!lastError_.empty()) {
            ImGui::Dummy(ImVec2(0, 8));
            ImGui::TextColored(kBad, "错误: %s", lastError_.c_str());
        }
        ImGui::End();
        return;
    }

    DrawHeader(*snap_);
    ImGui::Separator();
    if (!lastError_.empty()) {
        ImGui::TextColored(kBad, "错误: %s", lastError_.c_str());
        ImGui::Separator();
    }

    if (ImGui::BeginTabBar("tabs")) {
        if (ImGui::BeginTabItem("事件")) {
            DrawEvents(*snap_);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("PCR 比对")) {
            DrawPCRs(*snap_);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("TPM 信息")) {
            DrawTPM(*snap_);
            ImGui::EndTabItem();
        }
        // 驱动标签页仅当运行时证明 API 可用（Win11 25H2 + VBS/HVCI）才显示。
        if (snap_->driverTabVisible) {
            if (ImGui::BeginTabItem("驱动 (运行时证明)")) {
                DrawDrivers(*snap_);
                ImGui::EndTabItem();
            }
        }
        if (ImGui::BeginTabItem("原始日志")) {
            DrawRaw(*snap_);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

void App::DrawHeader(Snapshot& s) {
    ImVec4 vc;
    const char* vt = "?";
    if (s.verdictStatus == "verified") { vc = kGood; vt = "验证通过"; }
    else if (s.verdictStatus == "attention") { vc = kWarn; vt = "需要注意"; }
    else if (s.verdictStatus == "mismatch") { vc = kBad; vt = "比对不一致"; }
    else if (s.verdictStatus == "file") { vc = kInfo; vt = "归档日志"; }
    else vc = kGrey;

    ImGui::TextUnformatted("TPM 度量启动查看器");
    ImGui::SameLine();
    ImGui::TextDisabled("%s  |  %d 字节  |  加载于 %s", s.sourceName.c_str(), int(s.raw.size()),
                        s.loadedAt.c_str());

    ImGui::PushStyleColor(ImGuiCol_Text, vc);
    ImGui::TextUnformatted(vt);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::TextUnformatted(s.verdictText.c_str());
    ImGui::Text("PCR 比对: %d/%d 一致%s", s.verdictMatched, s.verdictTotal,
                s.digestFailures > 0 ? Format("  |  %d 个摘要校验失败", s.digestFailures).c_str() : "");

    if (!s.findings.empty() && ImGui::TreeNodeEx("findings", ImGuiTreeNodeFlags_DefaultOpen)) {
        for (auto& f : s.findings) {
            ImVec4 c = f.sev == 'g' ? kGood : f.sev == 'w' ? kWarn : f.sev == 'b' ? kBad : kInfo;
            const char* tag = f.sev == 'g' ? "[正常]" : f.sev == 'w' ? "[警告]"
                              : f.sev == 'b' ? "[严重]" : "[提示]";
            ImGui::TextColored(c, "%s", tag);
            ImGui::SameLine();
            ImGui::TextUnformatted(f.text.c_str());
        }
        ImGui::TreePop();
    }

    if (ImGui::Button("刷新")) {
        std::string e;
        if (!LoadLive(&e)) lastError_ = e;
    }
    ImGui::SameLine();
    if (ImGui::Button("打开日志文件...")) {
        std::wstring p = FileDialog(false);
        if (!p.empty()) {
            std::string e;
            if (!LoadFile(p, &e)) lastError_ = e;
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("保存原始日志...")) {
        std::wstring p = FileDialog(true);
        if (!p.empty()) {
            std::ofstream f(p.c_str(), std::ios::binary);
            if (f) f.write(reinterpret_cast<const char*>(s.raw.data()), std::streamsize(s.raw.size()));
            if (!f) lastError_ = "保存日志文件失败";
        }
    }
}

void App::DrawEvents(Snapshot& s) {
    static char filter[128] = "";
    const float avail = ImGui::GetContentRegionAvail().y;
    const float listW = ImGui::GetContentRegionAvail().x * 0.52f;

    ImGui::SetNextItemWidth(240);
    ImGui::InputText("##filter", filter, sizeof(filter));
    ImGui::SameLine();
    ImGui::TextDisabled("过滤（类型、类别、摘要）");

    float listH = avail - ImGui::GetFrameHeightWithSpacing();
    ImGui::BeginChild("evlist", ImVec2(listW, listH), ImGuiChildFlags_Borders);
    if (ImGui::BeginTable("events", 6,
                          ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
                              ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 36);
        ImGui::TableSetupColumn("PCR", ImGuiTableColumnFlags_WidthFixed, 40);
        ImGui::TableSetupColumn("类别", ImGuiTableColumnFlags_WidthFixed, 76);
        ImGui::TableSetupColumn("类型", ImGuiTableColumnFlags_WidthFixed, 190);
        ImGui::TableSetupColumn("摘要", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("摘要校验", ImGuiTableColumnFlags_WidthFixed, 64);
        ImGui::TableHeadersRow();
        for (auto& ev : s.log.events) {
            std::string disp = std::string(EventTypeName(ev.type)) + " " + CategoryName(ev.category) +
                               " " + ev.summary;
            if (!ContainsCI(disp, filter)) continue;
            const char* verify =
                ev.digestOK == 1 ? "通过" : ev.digestOK == -1 ? "失败" : "-";
            std::string rowJoined =
                Format("%d\t%d\t%s\t%s\t%s\t%s", ev.index, ev.pcr, CategoryName(ev.category),
                       EventTypeName(ev.type).c_str(), ev.summary.c_str(), verify);
            ImGui::PushID(ev.index);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            char id[16];
            std::snprintf(id, sizeof(id), "%d", ev.index);
            if (ImGui::Selectable(id, selected_ == ev.index, ImGuiSelectableFlags_SpanAllColumns))
                selected_ = ev.index;
            // 行右键菜单：Selectable 是 SpanAllColumns，整行任意位置右键都能弹。
            if (ImGui::BeginPopupContextItem("rowctx")) {
                if (ImGui::MenuItem("拷贝整行 (Tab 分隔)"))
                    ImGui::SetClipboardText(rowJoined.c_str());
                if (ImGui::MenuItem("拷贝摘要")) ImGui::SetClipboardText(ev.summary.c_str());
                if (!ev.data.empty() && ImGui::MenuItem("拷贝原始数据 (hex)"))
                    ImGui::SetClipboardText(BytesHexSpaced(ev.data.data(), ev.data.size()).c_str());
                if (!ev.data.empty() && ImGui::MenuItem("拷贝原始数据 (ASCII)"))
                    ImGui::SetClipboardText(BytesAscii(ev.data.data(), ev.data.size()).c_str());
                ImGui::EndPopup();
            }
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(Format("%d", ev.pcr).c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(CategoryName(ev.category));
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(EventTypeName(ev.type).c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(ev.summary.c_str());
            ImGui::TableNextColumn();
            if (ev.digestOK == 1) ImGui::TextColored(kGood, "通过");
            else if (ev.digestOK == -1) ImGui::TextColored(kBad, "失败");
            else ImGui::TextColored(kGrey, "-");
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();

    ImGui::SameLine();
    // HorizontalScrollbar：内容超宽出底部横向滚动条；Shift+滚轮横滚
    // （ImGui 1.91.8 内置 MouseWheelRequestAxisSwap，无需自己处理）。
    // 没有这个标志，详细信息/SIPA 值等长行会被窗口右边缘直接裁掉。
    ImGui::BeginChild("evdetail", ImVec2(0, listH), ImGuiChildFlags_Borders,
                      ImGuiWindowFlags_HorizontalScrollbar);
    if (selected_ >= 0 && selected_ < int(s.log.events.size()))
        DrawEventDetail(s, s.log.events[size_t(selected_)]);
    else
        ImGui::TextDisabled("在左侧选择一个事件。");
    ImGui::EndChild();
}

void App::DrawEventDetail(Snapshot& s, const Event& ev) {
    ImGui::Text("事件 #%d", ev.index);
    ImGui::SameLine();
    ImGui::TextDisabled("%s (0x%08X)", EventTypeName(ev.type).c_str(), ev.type);
    ImGui::Text("PCR: %d    类别: %s    偏移: 0x%zX    长度: %d", ev.pcr,
                CategoryName(ev.category), ev.offset, int(ev.length));
    if (!ev.summary.empty()) ImGui::TextWrapped("%s", ev.summary.c_str());

    if (!ev.flags.empty()) {
        ImGui::SeparatorText("标志");
        for (auto& f : ev.flags) {
            ImVec4 c = kGrey;
            if (f == "secureboot-off" || f == "separator-error" || f == "malformed" ||
                f == "no-authority" || f == "module-not-validated") c = kBad;
            else if (f == "test-signing" || f == "boot-debugging" || f == "kernel-debugging" ||
                     f == "hypervisor-debugging" || f == "flight-signing" ||
                     f == "code-integrity-off") c = kWarn;
            else if (f == "elam" || f == "vbs-enabled" || f == "hypervisor-enabled" ||
                     f == "bitlocker-unlocked") c = kGood;
            ImGui::TextColored(c, "%s", FlagName(f));
        }
    }

    if (!s.evDigests[ev.index].empty()) {
        ImGui::SeparatorText("摘要");
        int di = 0;
        for (auto& d : s.evDigests[ev.index]) {
            ImVec4 c = ev.digestOK == 1 ? kGood : ev.digestOK == -1 ? kBad : kGrey;
            ImGui::PushID(0x1000 + di);
            ImGui::TextColored(c, "%-8s", d.alg.c_str());
            ImGui::SameLine();
            MonoText(d.hex);
            CellCopyMenu(d.hex, "", 0, "拷贝摘要值");
            ImGui::PopID();
            di++;
        }
        if (ev.digestOK == 1)
            ImGui::TextColored(kGood, "重新计算校验通过 (%s)", ev.digestHow.c_str());
        else if (ev.digestOK == -1)
            ImGui::TextColored(kBad, "与重新计算的摘要不一致");
    }

    if (!s.evPcrAfter[ev.index].empty()) {
        ImGui::SeparatorText("此事件扩展后的 PCR 值");
        int pi = 0;
        for (auto& d : s.evPcrAfter[ev.index]) {
            ImGui::PushID(0x2000 + pi);
            ImGui::TextDisabled("%-8s", d.alg.c_str());
            ImGui::SameLine();
            MonoText(d.hex);
            CellCopyMenu(d.hex, "", 0, "拷贝 PCR 值");
            ImGui::PopID();
            pi++;
        }
    }

    if (!ev.fields.empty()) {
        ImGui::SeparatorText("详细信息");
        for (auto& f : ev.fields) {
            ImVec4 c = {0.92f, 0.92f, 0.94f, 1.0f};
            if (f.kind == "path") c = ImVec4(0.55f, 0.95f, 0.65f, 1.0f);
            else if (f.kind == "cert") c = kWarn;
            else if (f.kind == "warn") c = kBad;
            else if (f.kind == "hex") c = kGrey;
            else if (f.kind == "bool") c = kInfo;
            ImGui::TextDisabled("%s:", f.key.c_str());
            ImGui::SameLine();
            ImGui::TextColored(c, "%s", f.value.c_str());
        }
    }

    if (!ev.sipa.empty()) {
        ImGui::SeparatorText("SIPA (Windows 度量 TLV)");
        DrawSipaNodes(ev.sipa);
    }

    if (!ev.data.empty()) {
        ImGui::SeparatorText(Format("事件原始数据 (%d 字节)", int(ev.data.size())).c_str());
        DrawHexView("evhex", ev.data.data(), ev.data.size());
    }
}

void App::DrawSipaNodes(const std::vector<SipaNode>& nodes) {
    for (auto& n : nodes) {
        bool leaf = n.children.empty();
        ImGuiTreeNodeFlags fl = leaf ? ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen
                                     : ImGuiTreeNodeFlags_DefaultOpen;
        // ImGui 用"标签文本"生成控件 ID：两个节点名字相同（如 TRUSTBOUNDARY
        // 下面常见的两个 LOADEDMODULEAGGREGATION）就会 ID 冲突 —— 轻则弹
        // "conflicting ID" 错误框，重则 TreePop 弹错 ID 栈直接断言崩溃。
        // 修法：用节点地址 PushID 保证每个节点有独立 ID 作用域。
        ImGui::PushID(reinterpret_cast<const void*>(&n));
        // 关键：TreeNodeEx 返回值 = "节点当前是否展开"。
        //   展开 → 它压了 ID 栈（内部 TreePush），必须配对 TreePop
        //   折叠 → 它【什么都没压】直接 early-out，此时调 TreePop 就会
        //          多弹一次 ID 栈 —— 折叠节点必崩（两次崩溃的根因）。
        // 所以"递归画子节点 + TreePop"都必须包在 if(open) 里。
        bool open = ImGui::TreeNodeEx(n.name.c_str(), fl);
        // 树标签上右键 → 记录（此时"上一个 item" = 树节点）。
        bool rightOnNode = ImGui::IsMouseReleased(ImGuiMouseButton_Right) &&
                           ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenBlockedByPopup);
        if (!n.value.empty()) {
            ImVec4 c = {0.92f, 0.92f, 0.94f, 1.0f};
            if (n.kind == "bool") c = kInfo;
            else if (n.kind == "hex") c = kGrey;
            else if (n.kind == "module") c = kGood;
            ImGui::SameLine(260);
            ImGui::TextColored(c, "%s", n.value.c_str());
        } else if (n.size > 0) {
            ImGui::SameLine(260);
            ImGui::TextDisabled("%u 字节", n.size);
        }
        // 值文本上右键 → 记录（此时"上一个 item" = 值文本）。
        bool rightOnValue = ImGui::IsMouseReleased(ImGuiMouseButton_Right) &&
                            ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenBlockedByPopup);
        // 关键：必须先画完值再开弹窗。之前用 BeginPopupContextItem 挂在值
        // 绘制【之前】，弹窗打开帧它返回 true 后当前窗口切进弹窗，值文本
        // 被画进菜单顶部 → 菜单多一行（实测 bug）。
        if (rightOnNode || rightOnValue) ImGui::OpenPopup("sipactx");
        if (ImGui::BeginPopup("sipactx")) {
            if (ImGui::MenuItem("拷贝名称")) ImGui::SetClipboardText(n.name.c_str());
            if (!n.value.empty() && ImGui::MenuItem("拷贝值"))
                ImGui::SetClipboardText(n.value.c_str());
            if (!n.value.empty() && ImGui::MenuItem("拷贝整行 (名称 Tab 值)"))
                ImGui::SetClipboardText((n.name + "\t" + n.value).c_str());
            ImGui::EndPopup();
        }
        if (open && !leaf) {
            DrawSipaNodes(n.children);
            ImGui::TreePop();
        }
        ImGui::PopID();
    }
}

void App::DrawPCRs(Snapshot& s) {
    for (auto& b : s.banks) {
        std::string head = b.alg;
        if (b.partial)
            head += Format("  -  部分库 (%d/%d 个度量事件缺少摘要)", b.missing, b.measured);
        else
            head += Format("  -  %d/%d 一致", b.matched, b.total);
        if (!ImGui::CollapsingHeader(head.c_str(), ImGuiTreeNodeFlags_DefaultOpen)) continue;

        if (ImGui::BeginTable(Format("pcrs_%s", b.alg.c_str()).c_str(), 6,
                              ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
                                  ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("PCR", ImGuiTableColumnFlags_WidthFixed, 44);
            ImGui::TableSetupColumn("用途", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("事件数", ImGuiTableColumnFlags_WidthFixed, 60);
            ImGui::TableSetupColumn("期望值 (重放)", ImGuiTableColumnFlags_WidthFixed, 300);
            ImGui::TableSetupColumn("实际值 (TPM)", ImGuiTableColumnFlags_WidthFixed, 300);
            ImGui::TableSetupColumn("结果", ImGuiTableColumnFlags_WidthFixed, 56);
            ImGui::TableHeadersRow();
            for (auto& r : b.rows) {
                const char* matchTxt = r.match == 1 ? "一致" : r.match == -1 ? "不一致" : "无";
                std::string rowJoined = Format(
                    "%d\t%s\t%s\t%s\t%s\t%s", r.index, r.name.c_str(),
                    r.events > 0 ? Format("%d", r.events).c_str() : "-",
                    r.expected.empty() ? "(未比对)" : r.expected.c_str(),
                    r.actual.empty() ? "(不存在)" : r.actual.c_str(), matchTxt);
                ImGui::PushID(r.index);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                std::string c0 = Format("%d", r.index);
                ImGui::TextUnformatted(c0.c_str());
                CellCopyMenu(c0, rowJoined, 0);
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(r.name.c_str());
                CellCopyMenu(r.name, rowJoined, 1);
                ImGui::TableNextColumn();
                std::string c2 = r.events > 0 ? Format("%d", r.events) : std::string("-");
                ImGui::TextUnformatted(c2.c_str());
                CellCopyMenu(c2, rowJoined, 2);
                ImGui::TableNextColumn();
                std::string c3 = r.expected.empty() ? "(未比对)" : r.expected;
                MonoText(c3);
                CellCopyMenu(c3, rowJoined, 3);
                ImGui::TableNextColumn();
                std::string c4 = r.actual.empty() ? "(不存在)" : r.actual;
                MonoText(c4);
                CellCopyMenu(c4, rowJoined, 4);
                ImGui::TableNextColumn();
                if (r.match == 1) ImGui::TextColored(kGood, "一致");
                else if (r.match == -1) ImGui::TextColored(kBad, "不一致");
                else ImGui::TextColored(kGrey, "无");
                CellCopyMenu(matchTxt, rowJoined, 5);
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
    }
    if (s.banks.empty()) ImGui::TextDisabled("日志中没有可计算哈希的库。");
}

void App::DrawTPM(Snapshot& s) {
    ImGui::SeparatorText("设备信息 (Tbsi_GetDeviceInfo)");
    if (s.devOK) {
        const char* ver = s.dev.tpmVersion == 1 ? "1.2" : s.dev.tpmVersion == 2 ? "2.0" : "?";
        const char* itf = s.dev.tpmInterfaceType == 1   ? "TIS (独立 TPM)"
                          : s.dev.tpmInterfaceType == 2 ? "CRB"
                          : s.dev.tpmInterfaceType == 3 ? "命令/响应 (固件 TPM)"
                                                        : "?";
        ImGui::Text("TPM 版本: %s    接口: %s    版本号: %u", ver, itf, s.dev.tpmImpRevision);
    } else {
        ImGui::TextColored(kBad, "设备信息不可用: %s", s.devErr.c_str());
    }

    ImGui::SeparatorText("固定属性 (TPM2_GetCapability / PT_FIXED)");
    if (s.propsOK) {
        ImGui::Text("制造商:    %s", s.props.manufacturer.c_str());
        ImGui::Text("厂商字符串: %s", s.props.vendorString.c_str());
        ImGui::Text("固件版本:  %s", s.props.firmwareVersion.c_str());
        ImGui::Text("规范:      %s rev %u.%02u (级别 %u)", s.props.specFamily.c_str(),
                    s.props.specRevision / 100, s.props.specRevision % 100, s.props.specLevel);
        if (ImGui::CollapsingHeader("全部固定属性 (原始值)")) {
            if (ImGui::BeginTable("props", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
                                                  ImGuiTableFlags_BordersInnerV)) {
                ImGui::TableSetupColumn("属性", ImGuiTableColumnFlags_WidthFixed, 160);
                ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed, 80);
                ImGui::TableSetupColumn("值");
                ImGui::TableHeadersRow();
                for (auto& [id, v] : s.props.raw) {
                    std::string c0 = Format("0x%03X", id);
                    std::string c1 = Format("0x%08X", id);
                    std::string c2 = Format("%u (0x%X)", v, v);
                    std::string rowJoined = c0 + "\t" + c1 + "\t" + c2;
                    ImGui::PushID(int(id));
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(c0.c_str());
                    CellCopyMenu(c0, rowJoined, 0);
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(c1.c_str());
                    CellCopyMenu(c1, rowJoined, 1);
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(c2.c_str());
                    CellCopyMenu(c2, rowJoined, 2);
                    ImGui::PopID();
                }
                ImGui::EndTable();
            }
        }
    } else {
        ImGui::TextColored(kGrey, "属性不可用: %s", s.propsErr.c_str());
    }

    ImGui::SeparatorText("已分配的 PCR 哈希库 (TPM2_GetCapability / TPM_CAP_PCRS)");
    if (s.banksOK) {
        for (auto& b : s.tpmBanks)
            ImGui::Text("%s  (实现了 %d 个 PCR)", AlgName(b.alg).c_str(), int(b.pcrs.size()));
        if (s.tpmBanks.empty()) ImGui::TextDisabled("无");
    } else {
        ImGui::TextColored(kGrey, "哈希库不可用: %s", s.banksErr.c_str());
    }
    if (!s.pcrReadOK)
        ImGui::TextColored(kWarn, "PCR 读取不完整: %s", s.pcrReadErr.c_str());

    // Log header info.
    ImGui::SeparatorText("日志头 (TCG_EfiSpecIdEvent)");
    ImGui::Text("签名: %s    版本: %d.%d errata %d    加密敏捷: %s",
                s.log.spec.signature.c_str(), s.log.spec.major, s.log.spec.minor,
                s.log.spec.errata, s.log.spec.cryptoAgile ? "是" : "否");
    std::string algs;
    for (auto& a : s.log.spec.algorithms)
        algs += (algs.empty() ? "" : ", ") + AlgName(a.alg) + Format(" (%u 字节)", a.size);
    ImGui::Text("算法: %s", algs.c_str());
    ImGui::Text("事件数: %d    StartupLocality: %u    H-CRTM: %s    日志错误: %d",
                  int(s.log.events.size()), s.replay.startupLocality,
                  s.replay.hcrtm ? "有" : "无", int(s.log.errors.size()));
    for (auto& e : s.log.errors) ImGui::TextColored(kWarn, "%s", e.c_str());
}

// ---- x64dbg 风格 hex 视图 ------------------------------------------------

// x64dbg 内存窗口风格的 hex 视图：偏移列 | 16 字节 hex 格 | ASCII 列。
// 交互：左键点选、Shift+点击扩选、按住左键拖动扩展选区；视图内任意位置
// 右键弹拷贝菜单（带空格 hex / 连续 hex / ASCII / 全选），没选中时前三项置灰。
// 选择状态按 id 存进 ImGui 窗口 storage；数据长度变化时自动重置
// （同一个 "evhex" id 切到另一个事件时不残留旧选择）。
// 大数据用 ImGuiListClipper 只画可见行，几 MB 日志也不卡。
void App::DrawHexView(const char* id, const uint8_t* data, size_t size) {
    if (size == 0) return;
    ImGui::PushFont(gMonoFont ? gMonoFont : ImGui::GetFont());

    // 选择状态（per-view，跟随 ImGui storage 生命周期）。
    ImGuiStorage* st = ImGui::GetStateStorage();
    ImGuiID k = ImGui::GetID(id);
    int selA = st->GetInt(k + 1, -1);   // 锚点（点击起点）
    int selB = st->GetInt(k + 2, -1);   // 扩展端（拖动 / Shift 落点）
    if (st->GetInt(k + 3, -1) != (int)size) { selA = selB = -1; st->SetInt(k + 3, (int)size); }
    if (selA < 0 || selB < 0 || (size_t)selA >= size || (size_t)selB >= size) selA = selB = -1;

    ImGuiIO& io = ImGui::GetIO();
    const float cw   = ImGui::CalcTextSize("0").x;    // 等宽字符宽
    const float lineH = ImGui::GetTextLineHeight();
    const float hexW = cw * 2 + 3;                    // hex 格宽（"xx" + 右侧空隙）
    const float offX = cw * 8 + 12;                   // hex 区起点
    const float ascX = offX + 16 * (hexW + 4) + 12;   // ASCII 区起点
    const int   lines = (int)((size + 15) / 16);

    // 一个"字节格"（hex 或 ASCII 字符）：画格子 + 处理点击/拖选，返回选中态。
    // 注意 AllowWhenBlockedByActiveItem：按住左键拖动时起点格子是 ActiveId，
    // 会挡住滑过格子的 hover 判定，必须带这个 flag 才能拖选。
    auto cell = [&](int idx, const char* label, float w) {
        int lo = -1, hi = -1;
        if (selA >= 0 && selB >= 0) { lo = selA < selB ? selA : selB; hi = selA < selB ? selB : selA; }
        bool sel = lo >= 0 && idx >= lo && idx <= hi;
        ImGui::Selectable(label, sel, ImGuiSelectableFlags_None, ImVec2(w, lineH));
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem)) {
            if (ImGui::IsMouseClicked(0)) {
                if (io.KeyShift && selA >= 0) selB = idx;   // Shift：以锚点扩展
                else                    selA = selB = idx;  // 新选择
            } else if (ImGui::IsMouseDown(0) && ImGui::IsMouseDragging(0, 0.01f)) {
                selB = idx;                                  // 拖动扩展
            }
        }
    };

    // FramePadding=0：格子紧贴无内边距（ASCII 每字符一格才能对齐）；
    // ItemSpacing.y=0：行与行紧贴，拖选跨行不断线。
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,  ImVec2(2, 0));

    // 内容区左上角（第一可见行起点）：右键菜单触发区从这里算起。
    const ImVec2 p0 = ImGui::GetCursorScreenPos();
    ImGuiListClipper clipper;
    clipper.Begin(lines, lineH);
    while (clipper.Step()) {
        for (int line = clipper.DisplayStart; line < clipper.DisplayEnd; line++) {
            int off = line * 16;
            int n = size - (size_t)off < 16 ? (int)(size - (size_t)off) : 16;

            // 偏移列
            ImGui::TextDisabled("%08x", off);

            // hex 列：每字节一格
            for (int b = 0; b < n; b++) {
                ImGui::SameLine(offX + b * (hexW + 4));
                ImGui::PushID(off + b);
                char lbl[4];
                std::snprintf(lbl, sizeof(lbl), "%02x", data[off + b]);
                cell(off + b, lbl, hexW);
                ImGui::PopID();
            }

            // ASCII 列：每字符一格
            for (int b = 0; b < n; b++) {
                ImGui::SameLine(ascX + b * cw);
                ImGui::PushID(0x40000000 + off + b);   // 与 hex 格 ID 区分
                uint8_t c = data[off + b];
                char lbl[2] = { (c >= 0x20 && c <= 0x7E) ? (char)c : '.', 0 };
                cell(off + b, lbl, cw);
                ImGui::PopID();
            }
        }
    }
    ImGui::PopStyleVar(2);

    // 右键菜单（x64dbg 风格：视图内空白处也能弹）。
    // 触发区 = [第一可见行左上角, 窗口右下角] 的矩形。不能用
    // BeginPopupContextWindow —— 那会挂在整个宿主窗口上，右键点同一
    // 窗口里的 SIPA 树等其他控件也会弹出这个菜单（实测冲突）。
    const ImVec2 wmax(ImGui::GetWindowPos().x + ImGui::GetWindowSize().x,
                      ImGui::GetWindowPos().y + ImGui::GetWindowSize().y);
    ImVec2 b1(ascX + 16 * cw + 4, ImGui::GetCursorScreenPos().y);
    if (b1.x < wmax.x) b1.x = wmax.x;
    if (b1.y < wmax.y) b1.y = wmax.y;
    const ImVec2 mp = io.MousePos;
    if (ImGui::IsWindowHovered(ImGuiHoveredFlags_AllowWhenBlockedByPopup) &&
        ImGui::IsMouseReleased(ImGuiMouseButton_Right) &&
        mp.x >= p0.x && mp.y >= p0.y && mp.x <= b1.x && mp.y <= b1.y)
        ImGui::OpenPopup("hexctx");
    if (ImGui::BeginPopup("hexctx")) {
        int lo = -1, hi = -1;
        if (selA >= 0 && selB >= 0) { lo = selA < selB ? selA : selB; hi = selA < selB ? selB : selA; }
        bool has = lo >= 0;
        ImGui::BeginDisabled(!has);
        if (ImGui::MenuItem("拷贝选中 (hex 带空格)"))
            ImGui::SetClipboardText(BytesHexSpaced(data + lo, (size_t)(hi - lo + 1)).c_str());
        if (ImGui::MenuItem("拷贝选中 (hex 连续)"))
            ImGui::SetClipboardText(BytesHexCont(data + lo, (size_t)(hi - lo + 1)).c_str());
        if (ImGui::MenuItem("拷贝选中 (ASCII)"))
            ImGui::SetClipboardText(BytesAscii(data + lo, (size_t)(hi - lo + 1)).c_str());
        ImGui::EndDisabled();
        ImGui::Separator();
        if (ImGui::MenuItem("全选")) { selA = 0; selB = (int)size - 1; }
        ImGui::EndPopup();
    }

    st->SetInt(k + 1, selA);
    st->SetInt(k + 2, selB);
    ImGui::PopFont();
}

void App::DrawRaw(Snapshot& s) {
    ImGui::Text("完整日志: %d 字节", int(s.raw.size()));
    ImGui::TextDisabled("左键点选/拖选字节，Shift 扩选，右键弹拷贝菜单。");
    // 主窗口带 NoDecoration（含 NoScrollbar）。hex 视图用 ListClipper 只画
    // 可见行，几 MB 日志也不卡；包一层子窗口出垂直滚动条；窄窗口下
    // hex 三列总宽超窗时靠横向滚动条右拉。
    ImGui::BeginChild("rawhex", ImGui::GetContentRegionAvail(),
                      ImGuiChildFlags_None, ImGuiWindowFlags_NoBackground |
                      ImGuiWindowFlags_HorizontalScrollbar);
    DrawHexView("rawhex", s.raw.data(), s.raw.size());
    ImGui::EndChild();
}

void App::DrawDrivers(Snapshot& s) {
    if (!s.driversOK) {
        ImGui::TextColored(kGrey, "驱动报告不可用: %s", s.driversErr.c_str());
        return;
    }
    const DriverReportResult& r = s.drivers;

    // 报告元信息。
    ImGui::Text("已加载驱动: %d 条", int(r.drivers.size()));
    ImGui::SameLine();
    ImGui::TextDisabled("报告包 %zu 字节", r.packageSize);
    if (r.reportOverflowed)
        ImGui::TextColored(kWarn, "报告溢出：安全内核记录数超限，列表可能不完整。");
    if (r.partialReport)
        ImGui::TextColored(kWarn, "部分报告：只包含部分 NT 驱动。");
    ImGui::TextDisabled("含启动驱动: %s    Nonce: %s",
                        r.includeBootDrivers ? "是" : "否（启动驱动信息在 TCG 日志里）",
                        r.nonceHex.c_str());
    if (!r.packageNote.empty())
        ImGui::TextDisabled("%s", r.packageNote.c_str());

    ImGui::SeparatorText("驱动列表（安全内核 VTL1 签名视图，非内存枚举）");

    // 子窗口占满剩余空间：表格行数几百条，主窗口本身无滚动条，
    // 必须靠子窗口出垂直滚动条；列被拉宽后横向也用滚动条右拉。
    ImGui::BeginChild("drvlist", ImGui::GetContentRegionAvail(),
                      ImGuiChildFlags_None, ImGuiWindowFlags_NoBackground |
                      ImGuiWindowFlags_HorizontalScrollbar);
    if (ImGui::BeginTable("drivers", 7,
                          ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                              ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 34);
        ImGui::TableSetupColumn("内部名", ImGuiTableColumnFlags_WidthStretch, 190);
        ImGui::TableSetupColumn("加载次数", ImGuiTableColumnFlags_WidthFixed, 68);
        ImGui::TableSetupColumn("标志", ImGuiTableColumnFlags_WidthFixed, 120);
        ImGui::TableSetupColumn("OEM", ImGuiTableColumnFlags_WidthFixed, 100);
        ImGui::TableSetupColumn("镜像哈希", ImGuiTableColumnFlags_WidthStretch, 300);
        ImGui::TableSetupColumn("证书指纹", ImGuiTableColumnFlags_WidthStretch, 300);
        ImGui::TableHeadersRow();
        int idx = 0;
        for (auto& d : r.drivers) {
            ImGui::PushID(idx);
            // 行拷贝文本：Tab 分隔，粘进 Excel 自动分列。
            std::string flagsStr;
            if (d.unloaded)     flagsStr += "已卸载 ";
            if (d.bootDriver)   flagsStr += "启动驱动 ";
            if (d.hotPatchable) flagsStr += "可热补丁 ";
            if (flagsStr.empty()) flagsStr = "-";
            std::string rowJoined = Format("%d\t%s\t%u\t%s\t%s\t%s\t%s",
                                           idx, d.internalName.c_str(), d.loadCount,
                                           flagsStr.c_str(), d.oemName.c_str(),
                                           d.imageHash.c_str(), d.certThumb.c_str());
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(Format("%d", idx).c_str());
            CellCopyMenu(Format("%d", idx), rowJoined, 0);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(d.internalName.c_str());
            CellCopyMenu(d.internalName, rowJoined, 1);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(Format("%u", d.loadCount).c_str());
            CellCopyMenu(Format("%u", d.loadCount), rowJoined, 2);
            ImGui::TableNextColumn();
            {
                // 标志位：已卸载=黄，启动驱动/可热补丁=蓝。
                if (d.unloaded) ImGui::TextColored(kWarn, "已卸载");
                if (d.bootDriver) ImGui::TextColored(kInfo, "启动驱动");
                if (d.hotPatchable) ImGui::TextColored(kInfo, "可热补丁");
                if (!d.unloaded && !d.bootDriver && !d.hotPatchable)
                    ImGui::TextDisabled("-");
            }
            CellCopyMenu(flagsStr, rowJoined, 3);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(d.oemName.c_str());
            CellCopyMenu(d.oemName, rowJoined, 4);
            ImGui::TableNextColumn();
            MonoTextWrapped(d.imageHash.empty() ? "(无)" : d.imageHash);
            CellCopyMenu(d.imageHash, rowJoined, 5);
            ImGui::TableNextColumn();
            MonoTextWrapped(d.certThumb.empty() ? "(无)" : d.certThumb);
            CellCopyMenu(d.certThumb, rowJoined, 6);
            ImGui::PopID();
            idx++;
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();
}

} // namespace tcg
