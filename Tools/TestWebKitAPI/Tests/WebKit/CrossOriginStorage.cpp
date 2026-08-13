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
#include "CrossOriginStoragePolicy.h"
#include "CrossOriginStorageRateLimiter.h"

#include "Helpers/Test.h"
#include <WebCore/CrossOriginStorageLimits.h>
#include <wtf/Vector.h>
#include <wtf/text/MakeString.h>

namespace TestWebKitAPI {

using namespace WebCore::CrossOriginStorageLimits;

using namespace WebKit::CrossOriginStoragePolicy::PublicHashList;

// Packs |hexDigests| the way the generator does: sorted, fixed width, no delimiters. A fixture
// that skipped the sort would be testing a list no generator would ever produce, and the binary
// search would answer about it incorrectly for reasons that say nothing about the code.
static Vector<uint8_t> packList(const Vector<String>& hexDigests)
{
    Vector<Vector<uint8_t>> packed;
    for (auto& hex : hexDigests) {
        Vector<uint8_t> digest;
        for (unsigned index = 0; index < digestSize; ++index)
            digest.append(static_cast<uint8_t>((toASCIIHexValue(hex[index * 2]) << 4) | toASCIIHexValue(hex[index * 2 + 1])));
        packed.append(WTF::move(digest));
    }

    std::sort(packed.begin(), packed.end(), [](auto& a, auto& b) {
        return compareSpans(a.span(), b.span()) == std::strong_ordering::less;
    });

    Vector<uint8_t> contents;
    for (auto& digest : packed)
        contents.appendVector(digest);
    return contents;
}

static constexpr auto listedDigest = "6d567d7c2f46febcdeaf874614d63e3192ff3a844ee34f8bb63f4c5cf259f233"_s;

TEST(CrossOriginStoragePublicHashList, FindsListedDigestAndRejectsUnlistedOne)
{
    auto alsoListed = "0000000000000000000000000000000000000000000000000000000000000001"_s;
    auto list = packList({ listedDigest, alsoListed });

    EXPECT_TRUE(packedListContains(list.span(), "SHA-256"_s, listedDigest));
    EXPECT_TRUE(packedListContains(list.span(), "SHA-256"_s, alsoListed));

    // A hash that is not on the list must fail closed, indistinguishably from a genuine miss.
    EXPECT_FALSE(packedListContains(list.span(), "SHA-256"_s, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"_s));
}

TEST(CrossOriginStoragePublicHashList, MatchesAlgorithmNameCaseInsensitively)
{
    auto list = packList({ listedDigest });
    EXPECT_TRUE(packedListContains(list.span(), "sha-256"_s, listedDigest));
}

TEST(CrossOriginStoragePublicHashList, RejectsEveryAlgorithmOtherThanSHA256)
{
    // The published list only carries SHA-256 digests, so a wildcard-scoped entry hashed with any
    // other recognized algorithm can never clear this gate, whatever its value happens to be.
    auto list = packList({ listedDigest });
    EXPECT_FALSE(packedListContains(list.span(), "SHA-1"_s, listedDigest));
    EXPECT_FALSE(packedListContains(list.span(), "SHA-384"_s, listedDigest));
    EXPECT_FALSE(packedListContains(list.span(), "SHA-512"_s, listedDigest));
}

TEST(CrossOriginStoragePublicHashList, FailsClosedOnAnEmptyList)
{
    // What a missing or unreadable file degrades to. It must behave exactly like a genuinely empty
    // list, never like "everything is on the list": that is the direction a load failure has to
    // fail in, and the only direction that keeps a "*" entry from being disclosed on a bad read.
    EXPECT_FALSE(packedListContains({ }, "SHA-256"_s, listedDigest));
}

TEST(CrossOriginStoragePublicHashList, FailsClosedOnATruncatedList)
{
    // A list whose length is not a whole number of digests is corrupt. Searching it anyway would
    // misalign every comparison and answer about content that is not on the list at all.
    auto list = packList({ listedDigest });
    EXPECT_TRUE(packedListContains(list.span(), "SHA-256"_s, listedDigest));

    list.removeLast();
    EXPECT_FALSE(isWellFormedList(list.size()));
    EXPECT_FALSE(packedListContains(list.span(), "SHA-256"_s, listedDigest));
}

TEST(CrossOriginStoragePublicHashList, RejectsAMalformedHashValue)
{
    auto list = packList({ listedDigest });
    // Too short, too long, and the right length but not hexadecimal.
    EXPECT_FALSE(packedListContains(list.span(), "SHA-256"_s, String { listedDigest }.left(63)));
    EXPECT_FALSE(packedListContains(list.span(), "SHA-256"_s, makeString(listedDigest, "0"_s)));
    EXPECT_FALSE(packedListContains(list.span(), "SHA-256"_s, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"_s));
}

TEST(CrossOriginStorageRateLimiter, DeniesAfterTheBurstIsExhausted)
{
    // Assert the shape of the behavior, not an exact boundary: this is a real wall-clock token
    // bucket, so a refill tick landing between two consumes lets one extra request through
    // non-deterministically, and an exact-count assertion would fail intermittently for reasons
    // that have nothing to do with a bug.
    WebKit::CrossOriginStorageRateLimiter limiter;
    auto origin = "https://example.com"_s;

    unsigned allowed = 0;
    unsigned attempts = readProbeBurstCapacity * 2;
    bool wasDenied = false;
    for (unsigned index = 0; index < attempts; ++index) {
        if (limiter.tryConsume(origin, WebKit::CrossOriginStorageRateLimiter::ProbeType::Read))
            ++allowed;
        else
            wasDenied = true;
    }

    EXPECT_TRUE(wasDenied);
    EXPECT_GE(allowed, readProbeBurstCapacity);
    // Generous slack for refills that legitimately happened during the loop.
    EXPECT_LE(allowed, readProbeBurstCapacity + 100);
}

TEST(CrossOriginStorageRateLimiter, BudgetsReadsAndWritesSeparately)
{
    // Exhausting the write budget must not consume any of the read budget: the two exist for
    // different reasons and are deliberately sized differently.
    WebKit::CrossOriginStorageRateLimiter limiter;
    auto origin = "https://example.com"_s;

    for (unsigned index = 0; index < writeProbeBurstCapacity * 2; ++index)
        limiter.tryConsume(origin, WebKit::CrossOriginStorageRateLimiter::ProbeType::Write);

    EXPECT_TRUE(limiter.tryConsume(origin, WebKit::CrossOriginStorageRateLimiter::ProbeType::Read));
}

TEST(CrossOriginStorageRateLimiter, BudgetsEachOriginIndependently)
{
    // One origin burning through its budget must not throttle an unrelated one.
    WebKit::CrossOriginStorageRateLimiter limiter;
    auto noisy = "https://noisy.example"_s;
    auto quiet = "https://quiet.example"_s;

    for (unsigned index = 0; index < readProbeBurstCapacity * 2; ++index)
        limiter.tryConsume(noisy, WebKit::CrossOriginStorageRateLimiter::ProbeType::Read);

    EXPECT_TRUE(limiter.tryConsume(quiet, WebKit::CrossOriginStorageRateLimiter::ProbeType::Read));
}

} // namespace TestWebKitAPI
