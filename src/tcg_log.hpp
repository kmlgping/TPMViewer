// tcg_log.hpp — TCG PC Client event log parser (SHA1 and crypto-agile formats)
// plus the UEFI / Windows payload decoders. Mirrors the TCG log exposed by
// TBS (Tbsi_Get_TCG_Log) and the files under C:\Windows\Logs\MeasuredBoot.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "sipa.hpp"

namespace tcg {

// Event type codes from the TCG PC Client Platform Firmware Profile.
constexpr uint32_t EvPrebootCert         = 0x00000000;
constexpr uint32_t EvPostCode            = 0x00000001;
constexpr uint32_t EvUnused              = 0x00000002;
constexpr uint32_t EvNoAction            = 0x00000003;
constexpr uint32_t EvSeparator           = 0x00000004;
constexpr uint32_t EvAction              = 0x00000005;
constexpr uint32_t EvEventTag            = 0x00000006;
constexpr uint32_t EvSCRTMContents       = 0x00000007;
constexpr uint32_t EvSCRTMVersion        = 0x00000008;
constexpr uint32_t EvCPUMicrocode        = 0x00000009;
constexpr uint32_t EvPlatformConfigFlags = 0x0000000A;
constexpr uint32_t EvTableOfDevices      = 0x0000000B;
constexpr uint32_t EvCompactHash         = 0x0000000C;
constexpr uint32_t EvIPL                 = 0x0000000D;
constexpr uint32_t EvIPLPartitionData    = 0x0000000E;
constexpr uint32_t EvNonhostCode         = 0x0000000F;
constexpr uint32_t EvNonhostConfig       = 0x00000010;
constexpr uint32_t EvNonhostInfo         = 0x00000011;
constexpr uint32_t EvOmitBootDeviceEvts  = 0x00000012;
constexpr uint32_t EvPostCode2           = 0x00000013;

constexpr uint32_t EvEFIEventBase               = 0x80000000;
constexpr uint32_t EvEFIVariableDriverConfig    = 0x80000001;
constexpr uint32_t EvEFIVariableBoot            = 0x80000002;
constexpr uint32_t EvEFIBootServicesApplication = 0x80000003;
constexpr uint32_t EvEFIBootServicesDriver      = 0x80000004;
constexpr uint32_t EvEFIRuntimeServicesDriver   = 0x80000005;
constexpr uint32_t EvEFIGPTEvent                = 0x80000006;
constexpr uint32_t EvEFIAction                  = 0x80000007;
constexpr uint32_t EvEFIPlatformFirmwareBlob    = 0x80000008;
constexpr uint32_t EvEFIHandoffTables           = 0x80000009;
constexpr uint32_t EvEFIPlatformFirmwareBlob2   = 0x8000000A;
constexpr uint32_t EvEFIHandoffTables2          = 0x8000000B;
constexpr uint32_t EvEFIVariableBoot2           = 0x8000000C;
constexpr uint32_t EvEFIGPTEvent2               = 0x8000000D;
constexpr uint32_t EvEFIHCRTMEvent              = 0x80000010;
constexpr uint32_t EvEFIVariableAuthority       = 0x800000E0;
constexpr uint32_t EvEFISPDMFirmwareBlob        = 0x800000E1;
constexpr uint32_t EvEFISPDMFirmwareConfig      = 0x800000E2;
constexpr uint32_t EvEFISPDMDevicePolicy        = 0x800000E3;
constexpr uint32_t EvEFISPDMDeviceAuthority     = 0x800000E4;

std::string EventTypeName(uint32_t t);

// One digest of an event for a given bank.
struct Digest {
    uint16_t alg = 0;
    std::vector<uint8_t> value;
};

// A decoded key/value pair shown to the user.
// kind hints the UI: "" (text), "hex", "bool", "path", "cert", "warn".
struct Field {
    std::string key;
    std::string value;
    std::string kind;
};

// (algorithm, digest size) pair from the spec ID event.
struct AlgSize {
    uint16_t alg = 0;
    uint16_t size = 0;
};

// Log header (TCG_EfiSpecIdEvent).
struct SpecInfo {
    std::string signature;
    uint32_t platformClass = 0;
    uint8_t major = 0, minor = 0, errata = 0, uintnSize = 0;
    std::vector<AlgSize> algorithms;
    std::vector<uint8_t> vendorInfo;
    bool cryptoAgile = false;
};

// One parsed log entry.
struct Event {
    int index = 0;
    size_t offset = 0;
    size_t length = 0;
    uint32_t pcr = 0;
    uint32_t type = 0;
    std::vector<Digest> digests;
    std::vector<uint8_t> data;
    std::string category;  // firmware, secureboot, bootapp, windows, separator, ...

    // Decoded information.
    std::string summary;
    std::vector<Field> fields;
    std::vector<SipaNode> sipa;
    std::vector<std::string> flags;  // "separator-error", "test-signing", ...
    int digestOK = 0;                // 1 verified, -1 mismatch, 0 not verifiable
    std::string digestHow;           // "data" / "vardata"

    // Per bank, the replayed PCR value once this event has been extended
    // (filled by Replay).
    std::vector<Digest> pcrAfter;
};

// A fully parsed event log.
struct Log {
    std::vector<uint8_t> raw;
    SpecInfo spec;
    std::vector<Event> events;
    std::vector<std::string> errors;
};

// Parse decodes a raw TCG event log (SHA1 or crypto-agile format). Parse
// errors are collected in Log::errors (parse stops at the first bad event).
Log Parse(const std::vector<uint8_t>& raw);

// UEFI_VARIABLE_DATA view (pointers alias the input buffer).
struct UefiVar {
    std::string guid;
    std::string name;
    const uint8_t* data = nullptr;
    size_t dataLen = 0;
    bool ok = false;
};
UefiVar ParseUefiVariable(const uint8_t* data, size_t len);

// EFI_SIGNATURE_LIST decoding.
struct SigEntry {
    std::string owner;   // EFI_SIGNATURE_DATA owner GUID string
    std::vector<uint8_t> data;  // signature data (cert DER or hash)
    bool isCert = false;
    std::string subject;        // cert subject CN (only when isCert)
    std::string summary;
};
struct SigList {
    std::string type;   // GUID string
    std::vector<SigEntry> entries;
};
// Returns the lists decoded so far; on a malformed list, sets err and stops.
std::vector<SigList> ParseSignatureLists(const uint8_t* data, size_t len, std::string& err);

// Renders an EFI device path in UEFI shell text notation
// (PciRoot(0x0)/Pci(0x1,0x1)/NVMe(...)/HD(...)/\path).
std::string DevicePath(const uint8_t* b, size_t len);
inline std::string DevicePath(const std::vector<uint8_t>& v) {
    return DevicePath(v.data(), v.size());
}

} // namespace tcg
