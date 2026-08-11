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

#include "config.h"
#include "CrossOriginStoragePublicHashList.h"
#include "CrossOriginStorageRateLimiter.h"

#include "Helpers/Test.h"
#include <WebCore/CrossOriginStorageLimits.h>
#include <wtf/FileSystem.h>
#include <wtf/Vector.h>

namespace TestWebKitAPI {

using namespace WebCore::CrossOriginStorageLimits;

// Writes a packed Public Hash List containing exactly |digests|, sorted, and points the singleton
// at it. Returns the directory to clean up.
static String writePublicHashList(const Vector<String>& hexDigests)
{
    Vector<Vector<uint8_t>> packed;
    for (auto& hex : hexDigests) {
        Vector<uint8_t> digest;
        for (unsigned index = 0; index < 32; ++index)
            digest.append(static_cast<uint8_t>((toASCIIHexValue(hex[index * 2]) << 4) | toASCIIHexValue(hex[index * 2 + 1])));
        packed.append(WTF::move(digest));
    }

    // The lookup is a binary search, so the shipped file is sorted at generation time. A test
    // fixture that skipped this would be testing a file no generator would ever produce.
    std::sort(packed.begin(), packed.end(), [](auto& a, auto& b) {
        return compareSpans(a.span(), b.span()) == std::strong_ordering::less;
    });

    Vector<uint8_t> contents;
    for (auto& digest : packed)
        contents.appendVector(digest);

    auto directory = FileSystem::createTemporaryDirectory("CrossOriginStorageTest"_s);
    auto path = FileSystem::pathByAppendingComponent(directory, "list.dat"_s);
    auto file = FileSystem::openFile(path, FileSystem::FileOpenMode::Truncate);
    file.write(contents.span());
    file = { };

    WebKit::CrossOriginStoragePublicHashList::singleton().setDataPathForTesting(path);
    return directory;
}

class CrossOriginStoragePublicHashListTest : public testing::Test {
public:
    void TearDown() final
    {
        WebKit::CrossOriginStoragePublicHashList::singleton().clearForTesting();
        if (!m_directory.isEmpty())
            FileSystem::deleteNonEmptyDirectory(m_directory);
    }

protected:
    String m_directory;
};

TEST_F(CrossOriginStoragePublicHashListTest, FindsListedDigestAndRejectsUnlistedOne)
{
    auto listed = "6d567d7c2f46febcdeaf874614d63e3192ff3a844ee34f8bb63f4c5cf259f233"_s;
    auto alsoListed = "0000000000000000000000000000000000000000000000000000000000000001"_s;
    m_directory = writePublicHashList({ listed, alsoListed });

    auto& list = WebKit::CrossOriginStoragePublicHashList::singleton();
    EXPECT_EQ(list.sizeForTesting(), 2u);
    EXPECT_TRUE(list.contains("SHA-256"_s, listed));
    EXPECT_TRUE(list.contains("SHA-256"_s, alsoListed));

    // A hash that is not on the list must fail closed, indistinguishably from a genuine miss.
    EXPECT_FALSE(list.contains("SHA-256"_s, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"_s));
}

TEST_F(CrossOriginStoragePublicHashListTest, MatchesAlgorithmNameCaseInsensitively)
{
    auto listed = "6d567d7c2f46febcdeaf874614d63e3192ff3a844ee34f8bb63f4c5cf259f233"_s;
    m_directory = writePublicHashList({ listed });

    auto& list = WebKit::CrossOriginStoragePublicHashList::singleton();
    EXPECT_TRUE(list.contains("sha-256"_s, listed));
}

TEST_F(CrossOriginStoragePublicHashListTest, RejectsEveryAlgorithmOtherThanSHA256)
{
    // The published list only carries SHA-256 digests, so a wildcard-scoped entry hashed with any
    // other recognized algorithm can never clear this gate, whatever its value happens to be.
    auto listed = "6d567d7c2f46febcdeaf874614d63e3192ff3a844ee34f8bb63f4c5cf259f233"_s;
    m_directory = writePublicHashList({ listed });

    auto& list = WebKit::CrossOriginStoragePublicHashList::singleton();
    EXPECT_FALSE(list.contains("SHA-1"_s, listed));
    EXPECT_FALSE(list.contains("SHA-384"_s, listed));
    EXPECT_FALSE(list.contains("SHA-512"_s, listed));
}

TEST_F(CrossOriginStoragePublicHashListTest, FailsClosedWhenTheListCannotBeRead)
{
    // A missing file must behave exactly like a genuinely empty list, never like "everything is on
    // the list". This is the direction a load failure has to fail in.
    WebKit::CrossOriginStoragePublicHashList::singleton().setDataPathForTesting("/definitely/not/a/real/path/list.dat"_s);

    auto& list = WebKit::CrossOriginStoragePublicHashList::singleton();
    EXPECT_EQ(list.sizeForTesting(), 0u);
    EXPECT_FALSE(list.contains("SHA-256"_s, "6d567d7c2f46febcdeaf874614d63e3192ff3a844ee34f8bb63f4c5cf259f233"_s));
}

TEST_F(CrossOriginStoragePublicHashListTest, FailsClosedOnATruncatedList)
{
    // A file whose length is not a whole number of digests is corrupt. Loading it partially would
    // shift every subsequent digest and make lookups answer about the wrong content.
    m_directory = FileSystem::createTemporaryDirectory("CrossOriginStorageTest"_s);
    auto path = FileSystem::pathByAppendingComponent(m_directory, "truncated.dat"_s);
    auto file = FileSystem::openFile(path, FileSystem::FileOpenMode::Truncate);
    Vector<uint8_t> partial(31, static_cast<uint8_t>(0));
    file.write(partial.span());
    file = { };

    auto& list = WebKit::CrossOriginStoragePublicHashList::singleton();
    list.setDataPathForTesting(path);
    EXPECT_EQ(list.sizeForTesting(), 0u);
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
