/*
 * Copyright (C) 2026 Thomas Steiner. All rights reserved.
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

#include <wtf/Seconds.h>
#include <wtf/StdLibExtras.h>

namespace WebCore {

// Every constant here is an implementation choice, not mandated by
// https://wicg.github.io/cross-origin-storage/. The values match the ones used by the Servo,
// Ladybird, and Gecko implementations of this feature, so that a resource behaves the same way
// across engines in the cases where the specification deliberately leaves the choice open.
namespace CrossOriginStorageLimits {

// The user agent's "maximum origins list length". Enforced both when a list is first supplied
// (as a TypeError) and when one is later merged into an existing entry (as a silent truncation).
// Small enough that a list cannot serve as an undeclared substitute for "*".
static constexpr size_t maximumOriginsListLength = 100;

// A pending entry whose writer never closed or aborted is treated as abandoned after this long,
// so that neither a reader nor a later writer is blocked behind a write that will never finish.
static constexpr Seconds pendingEntryStalenessTimeout = 5_min;

// Per-requesting-origin token buckets. Every read is a probe, so reads are rate limited to bound
// hash enumeration; writes get their own smaller, slower budget shared between the create request
// and the write verification that follows it.
static constexpr uint32_t readProbeBurstCapacity = 2000;
static constexpr double readProbeRefillPerSecond = 20;
static constexpr uint32_t writeProbeBurstCapacity = 200;
static constexpr double writeProbeRefillPerSecond = 2;

// Bounds the rate limiter's own memory over a long session that visits many distinct origins.
static constexpr size_t rateLimiterOriginCap = 10000;

// GREASE'ing: occasionally report a disclosable entry as absent, so that a "found" response is
// never a fully reliable signal. Never applied to entries large enough that a spurious
// re-download would be clearly disproportionate to the privacy benefit.
static constexpr double greaseProbability = 0.01;
static constexpr uint64_t greaseSizeCeiling = 500 * KB;

// Two-tier storage budget. The global cap is a fraction of *total* disk capacity rather than
// currently-available free space, both to avoid disclosing real-time free-space information and
// to keep the registry's own growth from shrinking its own future budget.
static constexpr double globalBudgetDiskCapacityRatio = 0.6;
static constexpr double perOriginBudgetRatio = 0.2;

// An absolute ceiling on the *computed* budget, independent of the percentage math, as a defense
// against a platform API that misreports disk capacity.
static constexpr uint64_t globalBudgetCeiling = 100ULL * 1024 * MB;

// Caps how much a single seek()/truncate() can claim during a write session, checked before the
// resize is attempted. This is distinct from, and much coarser than, the authoritative budget
// check that runs at close() time.
static constexpr uint64_t writeSessionSizeCap = 4ULL * 1024 * MB;

} // namespace CrossOriginStorageLimits

} // namespace WebCore
