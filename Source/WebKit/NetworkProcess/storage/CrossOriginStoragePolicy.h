/*
 * Copyright (C) 2026 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

#include <WebCore/CrossOriginStorageLimits.h>
#include <WebCore/CrossOriginStorageRequestData.h>
#include <wtf/CryptographicallyRandomNumber.h>
#include <wtf/HashSet.h>
#include <wtf/Vector.h>
#include <wtf/WallTime.h>
#include <wtf/text/StringBuilder.h>
#include <wtf/text/StringCommon.h>
#include <wtf/text/StringToIntegerConversion.h>
#include <wtf/text/StringView.h>
#include <wtf/text/WTFString.h>

namespace WebKit {

// The decision-making half of CrossOriginStorageRegistry, separated from the half that owns
// handles, files, and IPC.
//
// The split is not cosmetic. These are the parts whose failure modes are hardest to observe from
// the outside -- an on-disk format that silently misparses, an eviction order that quietly
// prefers the wrong entry, a GREASE roll that is not actually bounded -- and they are exactly the
// parts that a test cannot reach through a live registry, whose symbols WebKit.framework does not
// export. Expressed as pure functions over plain values they are directly testable, with no disk,
// no process, and no exported internals.
namespace CrossOriginStoragePolicy {

using namespace WebCore::CrossOriginStorageLimits;

// MARK: - Storage budget

// Both figures derive from *total* disk capacity, never from currently available free space: free
// space moves as unrelated things fill the disk, so a budget keyed on it would leak real-time disk
// state to any page willing to trigger over-quota writes, and would make the registry's own growth
// shrink its own future budget.
inline uint64_t globalBudgetForVolumeCapacity(uint64_t volumeCapacity)
{
    auto budget = static_cast<uint64_t>(volumeCapacity * globalBudgetDiskCapacityRatio);
    // Independent of the percentage math, as a defense against a platform API that misreports
    // capacity: a pure percentage would silently inherit such an error instead of failing safe.
    return std::min(budget, globalBudgetCeiling);
}

inline uint64_t perOriginBudgetForGlobalBudget(uint64_t globalBudget)
{
    return static_cast<uint64_t>(globalBudget * perOriginBudgetRatio);
}

// MARK: - GREASE'ing

inline bool shouldGrease(uint64_t entrySize)
{
    // Never GREASE an entry large enough that a spurious re-download would be clearly
    // disproportionate to the privacy benefit: on a small file a false negative costs a cheap
    // re-fetch, but on gigabyte-scale weights it would impose a real, observable bandwidth cost --
    // and that cost difference is itself observable, which would defeat the purpose.
    if (entrySize >= greaseSizeCeiling)
        return false;

    // A predictable roll is not a roll at all: if an adversary can anticipate which requests get
    // GREASEd, the "found" signal becomes reliable again through the predictable gaps. This uses
    // the cryptographic RNG rather than whichever generator is fastest.
    static constexpr uint32_t resolution = 100000;
    return cryptographicallyRandomNumber<uint32_t>() % resolution < static_cast<uint32_t>(greaseProbability * resolution);
}

// MARK: - On-disk metadata record

// The persisted form of a written entry. Deliberately a separate type from the registry's own
// Entry: only a written entry is ever persisted, and only these fields survive a restart, so a
// format that mirrored the live struct would invite persisting state that cannot outlive the
// process (pending writers, handle bookkeeping) or reloading it into a half-initialized entry.
struct EntryRecord {
    // Bumped whenever the field order or meaning changes. A record whose version does not match
    // is discarded rather than guessed at.
    static constexpr unsigned formatVersion = 1;

    String algorithm;
    String value;
    uint64_t size { 0 };
    WallTime lastReadTime;
    WebCore::CrossOriginStorageOriginsScope originsScope { WebCore::CrossOriginStorageOriginsScope::SameSite };
    String attributedOrigin;
    Vector<String> origins;
    Vector<String> storingOrigins;

    String serialize() const
    {
        StringBuilder builder;
        builder.append(formatVersion, '\n');
        builder.append(algorithm, '\n');
        builder.append(value, '\n');
        builder.append(size, '\n');
        builder.append(static_cast<uint64_t>(lastReadTime.secondsSinceEpoch().milliseconds()), '\n');
        builder.append(static_cast<unsigned>(originsScope), '\n');
        builder.append(attributedOrigin, '\n');
        builder.append(origins.size(), '\n');
        for (auto& origin : origins)
            builder.append(origin, '\n');
        builder.append(storingOrigins.size(), '\n');
        for (auto& origin : storingOrigins)
            builder.append(origin, '\n');
        return builder.toString();
    }

    // Returns nullopt only for a record that is unusable on its face -- an unrecognized format
    // version, or a disclosure scope outside the enum. A record that parses but describes nothing
    // useful (an empty hash, say) is returned as-is and rejected by the caller, which is also the
    // only place that can cross-check it against the bytes file on disk.
    static std::optional<EntryRecord> parse(StringView contents)
    {
        // Empty entries must be preserved: this is a positional format, and an entry whose
        // attributed origin is empty would otherwise shift every field after it by one line.
        auto lines = contents.toString().splitAllowingEmptyEntries('\n');
        auto readLine = [&](size_t index) -> String {
            return index < lines.size() ? lines[index] : String { };
        };

        if (parseInteger<unsigned>(readLine(0)).value_or(0) != formatVersion)
            return std::nullopt;

        auto scope = parseInteger<unsigned>(readLine(5)).value_or(0);
        if (scope > static_cast<unsigned>(WebCore::CrossOriginStorageOriginsScope::Wildcard))
            return std::nullopt;

        EntryRecord record;
        record.algorithm = readLine(1);
        record.value = readLine(2);
        record.size = parseInteger<uint64_t>(readLine(3)).value_or(0);
        record.lastReadTime = WallTime::fromRawSeconds(parseInteger<uint64_t>(readLine(4)).value_or(0) / 1000.0);
        record.originsScope = static_cast<WebCore::CrossOriginStorageOriginsScope>(scope);
        record.attributedOrigin = readLine(6);

        size_t cursor = 7;
        auto readOriginList = [&](Vector<String>& target) {
            auto count = parseInteger<size_t>(readLine(cursor++)).value_or(0);
            count = std::min(count, maximumOriginsListLength);
            for (size_t index = 0; index < count; ++index) {
                auto origin = readLine(cursor++);
                if (!origin.isEmpty())
                    target.append(origin);
            }
        };
        readOriginList(record.origins);
        readOriginList(record.storingOrigins);

        return record;
    }
};

// MARK: - Eviction

// One entry's worth of the state eviction actually reasons about. The registry projects its live
// entries onto these before planning, so that the ordering and the two-pass policy below never
// depend on anything that cannot be written down in a test.
struct EvictionCandidate {
    String key;
    WallTime lastReadTime;
    uint64_t size { 0 };
    // The origin charged for these bytes, which is whichever origin's write first transitioned the
    // entry to written. Evicting the entry gives its bytes back to this origin, not to whoever
    // happens to be writing now.
    String attributedOrigin;
    // Set only when exactly one origin has stored these bytes. Pass one may reclaim such an entry
    // on that origin's behalf; a shared entry is never reclaimed that way, even by a co-owner.
    String soleStoringOrigin;
};

struct BudgetState {
    uint64_t totalBytes { 0 };
    uint64_t writingOriginBytes { 0 };
    uint64_t globalBudget { 0 };
    uint64_t perOriginBudget { 0 };
};

struct EvictionPlan {
    // False when no amount of permitted eviction can make room, in which case keysToEvict is empty:
    // a write that cannot succeed must not cost the user any data on its way to failing.
    bool fits { false };
    Vector<String> keysToEvict;
};

// Least-recently-read first, with the key breaking ties so that two entries never evicted in a
// different order from one run to the next just because the hash map iterated differently.
inline void sortEvictionCandidates(Vector<EvictionCandidate>& candidates)
{
    std::sort(candidates.begin(), candidates.end(), [](auto& a, auto& b) {
        return a.lastReadTime != b.lastReadTime ? a.lastReadTime < b.lastReadTime : codePointCompareLessThan(a.key, b.key);
    });
}

// |candidates| must already be restricted to entries that are safe to evict at all: written, with
// no writer still outstanding. Everything else about the decision lives here.
inline EvictionPlan planEviction(Vector<EvictionCandidate> candidates, const String& writingOrigin, uint64_t size, BudgetState state)
{
    if (!state.globalBudget || size > state.globalBudget || size > state.perOriginBudget)
        return { };

    sortEvictionCandidates(candidates);

    EvictionPlan plan;
    HashSet<String> evicted;
    auto evict = [&](const EvictionCandidate& candidate) {
        evicted.add(candidate.key);
        plan.keysToEvict.append(candidate.key);
        state.totalBytes = state.totalBytes > candidate.size ? state.totalBytes - candidate.size : 0;
        if (candidate.attributedOrigin == writingOrigin)
            state.writingOriginBytes = state.writingOriginBytes > candidate.size ? state.writingOriginBytes - candidate.size : 0;
    };

    // Pass one: an origin that has hit its own share may only ever reclaim its *own* sole-owned
    // entries. Never a shared entry, even one it co-owns, and never another origin's, so that one
    // origin writing a lot cannot force eviction of a different origin's data by being more
    // recent.
    if (state.writingOriginBytes + size > state.perOriginBudget) {
        for (auto& candidate : candidates) {
            if (state.writingOriginBytes + size <= state.perOriginBudget)
                break;
            if (candidate.soleStoringOrigin != writingOrigin)
                continue;
            evict(candidate);
        }

        if (state.writingOriginBytes + size > state.perOriginBudget)
            return { };
    }

    // Pass two: only once several different origins, each individually within their own share,
    // collectively exceed the global cap does eviction fall back to plain cross-origin LRU. That
    // is fair here, because it reflects genuine multi-tenant demand rather than one origin
    // crowding out another.
    if (state.totalBytes + size > state.globalBudget) {
        for (auto& candidate : candidates) {
            if (state.totalBytes + size <= state.globalBudget)
                break;
            if (evicted.contains(candidate.key))
                continue;
            evict(candidate);
        }

        if (state.totalBytes + size > state.globalBudget)
            return { };
    }

    plan.fits = true;
    return plan;
}

} // namespace CrossOriginStoragePolicy

} // namespace WebKit
