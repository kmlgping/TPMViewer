// tbs_api.hpp — thin wrapper over the Windows TPM Base Services (tbs.dll) API.
// Loads tbs.dll dynamically (no import lib needed) and exposes:
//   - Tbsi_Get_TCG_Log  : raw TCG event log of the current boot
//   - Tbsip_Submit_Command : raw TPM 2.0 commands (PCR_Read, GetCapability)
// Mirrors the Go reference implementation in .ref_bootviewer/internal/tbs.
#pragma once
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace tcg {

// TPM_DEVICE_INFO from tbs.h.
struct TbsDeviceInfo {
    uint32_t structVersion = 0;
    uint32_t tpmVersion = 0;       // 1 = TPM 1.2, 2 = TPM 2.0
    uint32_t tpmInterfaceType = 0; // 1 = TIS, 2 = CRB, 3 = command-response (fTPM etc.)
    uint32_t tpmImpRevision = 0;
};

// An allocated PCR bank on the TPM.
struct TbsBank {
    uint16_t alg = 0;
    std::vector<int> pcrs;
};

// Fixed TPM properties (TPM_CAP_TPM_PROPERTIES / PT_FIXED) we display.
struct TbsProperties {
    std::string manufacturer;
    std::string vendorString;
    std::string firmwareVersion;
    std::string specFamily;
    uint32_t specLevel = 0;
    uint32_t specRevision = 0;
    std::map<uint32_t, uint32_t> raw;
};

// Symbolic name for a TBS_RESULT code ("TBS_E_...", or "unknown").
std::string TbsResultName(uint32_t code);

// Queries basic TPM device info. Does not need a context.
bool TbsGetDeviceInfo(TbsDeviceInfo& out, std::string* err);

class TbsContext {
public:
    ~TbsContext();
    TbsContext(const TbsContext&) = delete;
    TbsContext& operator=(const TbsContext&) = delete;

    // Returns nullptr and sets err if tbs.dll is missing or the context
    // cannot be created.
    static std::unique_ptr<TbsContext> Open(std::string* err);

    // Raw TCG event log (SRTM / Windows Boot Configuration Log).
    bool GetTCGLog(std::vector<uint8_t>& out, std::string* err);

    // Reads PCRs 0..23 for the given hash bank. PCRs the TPM does not
    // implement for that bank are absent from the map.
    bool ReadPCRs(uint16_t alg, std::map<int, std::vector<uint8_t>>& out, std::string* err);

    // PCR banks currently allocated on the TPM.
    bool ActiveBanks(std::vector<TbsBank>& out, std::string* err);

    // TPM_CAP_TPM_PROPERTIES / PT_FIXED.
    bool FixedProperties(TbsProperties& out, std::string* err);

private:
    TbsContext() = default;
    bool Submit(const uint8_t* cmd, size_t cmdLen, std::vector<uint8_t>& resp, std::string* err);
    void* h_ = nullptr;
};

} // namespace tcg
