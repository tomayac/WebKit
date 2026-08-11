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

#include <wtf/HashMap.h>
#include <wtf/MonotonicTime.h>
#include <wtf/text/WTFString.h>

namespace WebKit {

// Per-requesting-origin token buckets for Cross-Origin Storage.
//
// Every read is a probe: its found/not-found/still-pending outcome is directly observable by the
// calling script, so an origin could otherwise brute-force hashes to infer what is cross-origin
// cached. Writes get their own, smaller and slower, budget: a create request has no return value
// at all, so it is not a fingerprinting oracle, but it is still unbounded registry churn and disk
// I/O if flooded. The create request and the write verification that follows it share one budget,
// since the former is just the first step of the latter.
//
// Denial is never itself observable: a caller over budget gets exactly the response a genuine
// miss would produce, so that the limiter cannot be turned into its own side channel.
class CrossOriginStorageRateLimiter {
public:
    CrossOriginStorageRateLimiter() = default;

    enum class ProbeType : bool { Read, Write };

    // Returns false when the origin is over budget.
    bool tryConsume(const String& origin, ProbeType);

    void clear();

private:
    struct Bucket {
        double tokens { 0 };
        MonotonicTime lastRefill;
    };

    using BucketMap = HashMap<String, Bucket>;

    static bool tryConsume(BucketMap&, const String& origin, double capacity, double refillPerSecond);
    // A bucket's own last-refill timestamp doubles as its recency signal, so capping the map costs
    // no extra bookkeeping. Worst case for an evicted origin is a reset burst, which is what it
    // would have seen after a process restart anyway.
    static void evictLeastRecentlyUsedIfNeeded(BucketMap&);

    BucketMap m_readBuckets;
    BucketMap m_writeBuckets;
};

} // namespace WebKit
