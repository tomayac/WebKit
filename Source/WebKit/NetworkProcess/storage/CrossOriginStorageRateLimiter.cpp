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

#include "config.h"
#include "CrossOriginStorageRateLimiter.h"

#include <WebCore/CrossOriginStorageLimits.h>

namespace WebKit {

using namespace WebCore::CrossOriginStorageLimits;

void CrossOriginStorageRateLimiter::evictLeastRecentlyUsedIfNeeded(BucketMap& buckets)
{
    if (buckets.size() < rateLimiterOriginCap)
        return;

    String leastRecentlyUsed;
    auto oldestRefill = MonotonicTime::infinity();
    for (auto& entry : buckets) {
        if (entry.value.lastRefill < oldestRefill) {
            oldestRefill = entry.value.lastRefill;
            leastRecentlyUsed = entry.key;
        }
    }

    if (!leastRecentlyUsed.isNull())
        buckets.remove(leastRecentlyUsed);
}

bool CrossOriginStorageRateLimiter::tryConsume(BucketMap& buckets, const String& origin, double capacity, double refillPerSecond)
{
    auto now = MonotonicTime::now();
    auto iterator = buckets.find(origin);
    if (iterator == buckets.end()) {
        evictLeastRecentlyUsedIfNeeded(buckets);
        buckets.add(origin, Bucket { capacity - 1, now });
        return true;
    }

    auto& bucket = iterator->value;
    auto elapsed = (now - bucket.lastRefill).seconds();
    if (elapsed > 0)
        bucket.tokens = std::min(capacity, bucket.tokens + elapsed * refillPerSecond);
    // Update on every attempt, allowed or denied, so the timestamp stays a true recency signal.
    bucket.lastRefill = now;

    if (bucket.tokens < 1)
        return false;

    bucket.tokens -= 1;
    return true;
}

bool CrossOriginStorageRateLimiter::tryConsume(const String& origin, ProbeType type)
{
    if (type == ProbeType::Read)
        return tryConsume(m_readBuckets, origin, readProbeBurstCapacity, readProbeRefillPerSecond);

    return tryConsume(m_writeBuckets, origin, writeProbeBurstCapacity, writeProbeRefillPerSecond);
}

void CrossOriginStorageRateLimiter::clear()
{
    m_readBuckets.clear();
    m_writeBuckets.clear();
}

} // namespace WebKit
