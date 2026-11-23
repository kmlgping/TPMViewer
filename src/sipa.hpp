// sipa.hpp — SIPA (Windows "Secure Integrity Platform Attestation") TLV decoder.
//
// Windows bootmgr / winload / CI write TLV records into PCRs 11-14 via
// EV_EVENT_TAG. Each record: {type u32, size u32, data[size]}; types with the
// 0x40000000 aggregation bit contain nested records.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace tcg {

struct SipaNode {
    uint32_t type = 0;
    std::string name;      // symbolic name or "SIPA_0x%08X"
    std::string category;  // e.g. "OSPARAMETER", "AGGREGATION, CONTAINER"
    uint32_t size = 0;     // payload size (excludes the 8-byte header)
    std::vector<uint8_t> raw;
    std::string value;     // formatted value
    std::string kind;      // "bool" | "text" | "hex" | "module" | "container"
    std::vector<SipaNode> children;
};

// Decode a SIPA TLV stream. Nodes with the aggregation bit are recursed into
// (depth-capped at 8). Stops early on a truncated record.
std::vector<SipaNode> DecodeSipa(const uint8_t* data, size_t len);

// True when the top-level decode consumed exactly `total` bytes and at least
// one node has a known symbolic name (guards against random EV_EVENT_TAG data).
bool SipaLooksValid(const std::vector<SipaNode>& nodes, size_t total);

// One-line human description of a decoded SIPA event.
std::string SipaSummary(const std::vector<SipaNode>& nodes);

// Security-relevant flags found in the tree: "test-signing", "code-integrity-off",
// "vbs-enabled", "bitlocker-unlocked", ...
std::vector<std::string> CollectSipaFlags(const std::vector<SipaNode>& nodes);

// Flatten every LOADEDMODULEAGGREGATION entry out of the tree.
std::vector<const SipaNode*> SipaModules(const std::vector<SipaNode>& nodes);

std::string SipaName(uint32_t type);
std::string SipaCategory(uint32_t type);

} // namespace tcg
