// app.hpp — application state + ImGui UI for the TPM measured boot viewer.
#pragma once
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "driver_report.hpp"
#include "replay.hpp"
#include "tcg_log.hpp"
#include "tbs_api.hpp"

namespace tcg {

class App {
public:
    App();

    // Loads the log of the current boot through TBS and reads live PCR
    // values + TPM properties. Returns false with err set on failure.
    bool LoadLive(std::string* err);
    // Loads and parses a log file (no live TPM comparison).
    bool LoadFile(const std::wstring& path, std::string* err);

    bool HasData() const { return snap_ != nullptr; }
    void Draw();

private:
    // Pre-formatted display data built once per load so the UI only draws
    // strings each frame.
    struct DispDigest {
        std::string alg;
        std::string hex;
        bool ok = false; // false -> grey (not verified against data)
    };
    struct DispPCRRow {
        int index = 0;
        std::string name;
        std::string expected;
        std::string actual;
        int match = 0;
        int events = 0;
    };
    struct DispBank {
        std::string alg;
        uint16_t algId = 0;
        bool partial = false;
        int missing = 0;
        int measured = 0;
        int matched = 0;
        int total = 0;
        std::vector<DispPCRRow> rows;
    };
    struct Finding {
        char sev = 'i'; // g=good i=info w=warn b=bad
        std::string text;
    };
    struct Snapshot {
        bool fromFile = false;
        std::wstring filePath;
        std::string sourceName;
        std::string loadedAt;
        std::vector<uint8_t> raw;
        Log log;
        ReplayResult replay;

        TbsDeviceInfo dev;
        bool devOK = false;
        std::string devErr;
        TbsProperties props;
        bool propsOK = false;
        std::string propsErr;
        std::vector<TbsBank> tpmBanks;
        bool banksOK = false;
        std::string banksErr;
        // live PCR values per bank (empty for file loads)
        std::map<uint16_t, std::map<int, std::vector<uint8_t>>> actual;
        bool pcrReadOK = false;
        std::string pcrReadErr;

        // 运行时证明驱动报告（仅实时模式拉取）。
        // 拉取失败/系统不支持（< Win11 25H2 或未开 VBS/HVCI）时
        // driversOK=false 且不显示"驱动"标签页。
        DriverReportResult drivers;
        bool driversOK = false;
        std::string driversErr;
        bool driverTabVisible = false;

        // display cache
        std::vector<DispDigest> digests;   // flattened per event, indexed like log.events
        std::vector<std::vector<DispDigest>> evDigests;
        std::vector<std::vector<DispDigest>> evPcrAfter;
        std::vector<std::string> evHex;    // hex dump of event data
        std::string rawHex;                // hex dump of the whole log
        bool rawHexBuilt = false;
        std::vector<DispBank> banks;
        std::vector<Finding> findings;
        std::string verdictStatus;         // verified | attention | mismatch | notpm | file
        std::string verdictText;
        int verdictMatched = 0, verdictTotal = 0, digestFailures = 0;
    };

    void BuildDisplay(Snapshot& s);
    void DrawHeader(Snapshot& s);
    void DrawEvents(Snapshot& s);
    void DrawEventDetail(Snapshot& s, const Event& ev);
    void DrawPCRs(Snapshot& s);
    void DrawTPM(Snapshot& s);
    void DrawRaw(Snapshot& s);
    void DrawDrivers(Snapshot& s);
    static void DrawSipaNodes(const std::vector<SipaNode>& nodes);

    std::unique_ptr<Snapshot> snap_;
    int selected_ = -1;
    std::string lastError_;
};

} // namespace tcg
