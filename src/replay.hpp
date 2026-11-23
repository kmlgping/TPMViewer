// replay.hpp — PCR replay: compute expected PCR values from the log and
// compare them against values read from the TPM.
#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "tcg_log.hpp"

namespace tcg {

// Reset value of a PCR for a bank with the given digest size. PCR 17-22
// (DRTM / locality 4) reset to all-ones on TPM 2.0; the rest to zero.
// startupLocality (from the EV_NO_ACTION StartupLocality event) seeds PCR 0
// with the locality number in its last byte.
std::vector<uint8_t> InitialPCR(int index, size_t size, uint8_t startupLocality);

struct ReplayResult {
    // expected[alg][pcr] = digest after replaying all events (24 entries).
    std::map<uint16_t, std::vector<std::vector<uint8_t>>> expected;
    // eventCount[pcr] = number of events extended into that PCR.
    int eventCount[24] = {};
    // Banks present in the log (in header order), hashable algorithms only.
    std::vector<uint16_t> banks;
    // StartupLocality seen in the log, if any (4 when an H-CRTM event exists).
    uint8_t startupLocality = 0;
    // True when the log carries an EV_EFI_HCRTM_EVENT.
    bool hcrtm = false;
    // missing[alg] counts measured events that carry no digest for that bank;
    // such a bank cannot be replayed from the log (boot manager caps it).
    std::map<uint16_t, int> missing;
    // Number of events that extend a PCR (EV_NO_ACTION and out-of-range
    // PCRs excluded).
    int measured = 0;

    bool Partial(uint16_t alg) const {
        auto it = missing.find(alg);
        return it != missing.end() && it->second > 0;
    }
};

// Computes the expected final PCR values for every bank in the log and
// annotates each event with the PCR value after its extension (PCRAfter).
ReplayResult Replay(Log& lg);

// Comparison result for one PCR in one bank.
struct PCRStatus {
    int index = 0;
    uint16_t alg = 0;
    std::vector<uint8_t> expected;
    std::vector<uint8_t> actual;
    int match = 0;   // 1 = equal, -1 = different, 0 = no TPM value available
    int events = 0;  // measured event count for this PCR

    std::string String() const;
};

// Matches replayed values against PCRs read from the TPM. A partial bank is
// never compared: its rows carry the TPM value and the event count but no
// expected value and match == 0.
std::vector<PCRStatus> Compare(const ReplayResult& r, uint16_t alg,
                               const std::map<int, std::vector<uint8_t>>& actual);

} // namespace tcg
