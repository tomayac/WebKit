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
#include "CrossOriginStorageRegistry.h"
#include "FileSystemStorageHandleRegistry.h"

#include "Helpers/Test.h"
#include <WebCore/CrossOriginStorageLimits.h>
#include <wtf/FileSystem.h>
#include <wtf/RunLoop.h>
#include <wtf/WorkQueue.h>
#include <wtf/threads/BinarySemaphore.h>

namespace TestWebKitAPI {

using namespace WebCore::CrossOriginStorageLimits;

// The registry asserts it is never touched from the main thread -- it lives on
// NetworkStorageManager's work queue, which is what lets it hold no locks. So
// these tests drive it from a work queue of their own and block until each step
// finishes, rather than relaxing that requirement for the tests' convenience.
static void runOnRegistryQueue(NOESCAPE const Function<void()>& work)
{
    Ref queue = WorkQueue::create("CrossOriginStorageRegistryTest"_s);
    BinarySemaphore semaphore;
    queue->dispatch([&] {
        work();
        semaphore.signal();
    });
    semaphore.wait();
}

static String makeRegistryDirectory()
{
    // createTemporaryFile() gives a unique name; the registry wants a directory
    // at that path, so take the name and replace the file with one.
    auto path = FileSystem::createTemporaryFile("CrossOriginStorageRegistryTest"_s);
    FileSystem::deleteFile(path);
    FileSystem::makeAllDirectories(path);
    return path;
}

// A syntactically valid, distinct SHA-256 value. The registry validates the
// shape of what it is given, so tests cannot use arbitrary labels.
static String hashValue(unsigned seed)
{
    StringBuilder builder;
    builder.append(hex(seed, 8, Lowercase));
    while (builder.length() < 64)
        builder.append('0');
    return builder.toString();
}

class CrossOriginStorageRegistryTest : public testing::Test {
public:
    void TearDown() final
    {
        if (!m_directory.isEmpty())
            FileSystem::deleteNonEmptyDirectory(m_directory);
    }

protected:
    String m_directory;
};

TEST_F(CrossOriginStorageRegistryTest, WrittenEntriesSurviveAcrossRegistryLifetimes)
{
    m_directory = makeRegistryDirectory();
    auto origin = "https://storer.example"_s;

    runOnRegistryQueue([&] {
        Ref handles = WebKit::FileSystemStorageHandleRegistry::create();
        Ref registry = WebKit::CrossOriginStorageRegistry::create(String { m_directory }, handles, std::nullopt);
        registry->addWrittenEntryForTesting("SHA-256"_s, hashValue(1), origin, 128,
            WebCore::CrossOriginStorageOriginsScope::Wildcard, { }, WallTime::now());
        registry->addWrittenEntryForTesting("SHA-256"_s, hashValue(2), origin, 256,
            WebCore::CrossOriginStorageOriginsScope::List, { "https://listed.example"_s }, WallTime::now());
        EXPECT_EQ(registry->entryCountForTesting(), 2u);
    });

    // A second registry over the same directory stands in for a browser
    // restart: nothing is carried over in memory, so everything asserted below
    // came back off disk.
    runOnRegistryQueue([&] {
        Ref handles = WebKit::FileSystemStorageHandleRegistry::create();
        Ref registry = WebKit::CrossOriginStorageRegistry::create(String { m_directory }, handles, std::nullopt);
        EXPECT_EQ(registry->entryCountForTesting(), 2u);
        EXPECT_TRUE(registry->containsWrittenEntryForTesting("SHA-256"_s, hashValue(1)));
        EXPECT_TRUE(registry->containsWrittenEntryForTesting("SHA-256"_s, hashValue(2)));
        // Usage is recomputed from what was loaded, not persisted as a total.
        EXPECT_EQ(registry->bytesForOriginForTesting(origin), 384u);
        EXPECT_EQ(registry->totalBytes(), 384u);
    });
}

TEST_F(CrossOriginStorageRegistryTest, ReloadsAnEntryWhoseAttributedOriginIsEmpty)
{
    // Regression test. The metadata format is positional, and the reader used a
    // splitter that discards empty fields, so an entry with an empty attributed
    // origin shifted every subsequent field by one line and was dropped -- or
    // worse, misparsed -- on reload. An entry can legitimately reach that state
    // through a site-scoped clear that removes the attributed origin while
    // another storing origin remains.
    m_directory = makeRegistryDirectory();

    runOnRegistryQueue([&] {
        Ref handles = WebKit::FileSystemStorageHandleRegistry::create();
        Ref registry = WebKit::CrossOriginStorageRegistry::create(String { m_directory }, handles, std::nullopt);
        registry->addWrittenEntryForTesting("SHA-256"_s, hashValue(3), emptyString(), 64,
            WebCore::CrossOriginStorageOriginsScope::Wildcard, { }, WallTime::now());
        registry->addWrittenEntryForTesting("SHA-256"_s, hashValue(4), "https://after.example"_s, 64,
            WebCore::CrossOriginStorageOriginsScope::SameSite, { }, WallTime::now());
    });

    runOnRegistryQueue([&] {
        Ref handles = WebKit::FileSystemStorageHandleRegistry::create();
        Ref registry = WebKit::CrossOriginStorageRegistry::create(String { m_directory }, handles, std::nullopt);
        EXPECT_TRUE(registry->containsWrittenEntryForTesting("SHA-256"_s, hashValue(3)));
        // The entry written *after* the one with the empty field is the one a
        // positional-parsing bug would corrupt.
        EXPECT_TRUE(registry->containsWrittenEntryForTesting("SHA-256"_s, hashValue(4)));
    });
}

TEST_F(CrossOriginStorageRegistryTest, EvictsAnOriginsOwnEntriesOldestReadFirst)
{
    m_directory = makeRegistryDirectory();
    auto origin = "https://greedy.example"_s;

    runOnRegistryQueue([&] {
        Ref handles = WebKit::FileSystemStorageHandleRegistry::create();
        // A tiny reported volume capacity is what makes the budget reachable in
        // a test: it is a fraction of total capacity, so on a real disk nothing
        // a test could plausibly write would ever approach it.
        Ref registry = WebKit::CrossOriginStorageRegistry::create(String { m_directory }, handles, 10 * KB);
        auto perOrigin = static_cast<uint64_t>(registry->globalBudgetForTesting() * perOriginBudgetRatio);
        ASSERT_GT(perOrigin, 300u);

        auto now = WallTime::now();
        auto size = perOrigin / 3;
        // Distinct read times, oldest first, so eviction order is observable.
        registry->addWrittenEntryForTesting("SHA-256"_s, hashValue(10), origin, size,
            WebCore::CrossOriginStorageOriginsScope::SameSite, { }, now - 300_s);
        registry->addWrittenEntryForTesting("SHA-256"_s, hashValue(11), origin, size,
            WebCore::CrossOriginStorageOriginsScope::SameSite, { }, now - 200_s);
        registry->addWrittenEntryForTesting("SHA-256"_s, hashValue(12), origin, size,
            WebCore::CrossOriginStorageOriginsScope::SameSite, { }, now - 100_s);

        EXPECT_TRUE(registry->makeRoomForWriteForTesting(origin, size));

        // Oldest-read-first: the entry nobody has read in the longest goes, and
        // the two more recently read ones stay.
        EXPECT_FALSE(registry->containsWrittenEntryForTesting("SHA-256"_s, hashValue(10)));
        EXPECT_TRUE(registry->containsWrittenEntryForTesting("SHA-256"_s, hashValue(11)));
        EXPECT_TRUE(registry->containsWrittenEntryForTesting("SHA-256"_s, hashValue(12)));
    });
}

TEST_F(CrossOriginStorageRegistryTest, OneOriginOverItsShareNeverEvictsAnothersEntries)
{
    // The point of the per-origin share: an origin writing a lot must not be
    // able to push out a different origin's data merely by being more recent.
    m_directory = makeRegistryDirectory();
    auto greedy = "https://greedy.example"_s;
    auto bystander = "https://bystander.example"_s;

    runOnRegistryQueue([&] {
        Ref handles = WebKit::FileSystemStorageHandleRegistry::create();
        Ref registry = WebKit::CrossOriginStorageRegistry::create(String { m_directory }, handles, 10 * KB);
        auto perOrigin = static_cast<uint64_t>(registry->globalBudgetForTesting() * perOriginBudgetRatio);
        ASSERT_GT(perOrigin, 300u);
        auto size = perOrigin / 3;

        auto now = WallTime::now();
        // The bystander's entry is by far the least recently read, so a policy
        // that only sorted by recency would evict it first.
        registry->addWrittenEntryForTesting("SHA-256"_s, hashValue(20), bystander, size,
            WebCore::CrossOriginStorageOriginsScope::SameSite, { }, now - 10000_s);
        registry->addWrittenEntryForTesting("SHA-256"_s, hashValue(21), greedy, size,
            WebCore::CrossOriginStorageOriginsScope::SameSite, { }, now - 200_s);
        registry->addWrittenEntryForTesting("SHA-256"_s, hashValue(22), greedy, size,
            WebCore::CrossOriginStorageOriginsScope::SameSite, { }, now - 100_s);

        EXPECT_TRUE(registry->makeRoomForWriteForTesting(greedy, size));

        EXPECT_TRUE(registry->containsWrittenEntryForTesting("SHA-256"_s, hashValue(20)));
        EXPECT_EQ(registry->bytesForOriginForTesting(bystander), size);
    });
}

TEST_F(CrossOriginStorageRegistryTest, RejectsAWriteLargerThanAnOriginCouldEverStore)
{
    m_directory = makeRegistryDirectory();

    runOnRegistryQueue([&] {
        Ref handles = WebKit::FileSystemStorageHandleRegistry::create();
        Ref registry = WebKit::CrossOriginStorageRegistry::create(String { m_directory }, handles, 10 * KB);
        // Larger than the whole global budget, so no amount of eviction helps.
        EXPECT_FALSE(registry->makeRoomForWriteForTesting("https://huge.example"_s,
            registry->globalBudgetForTesting() + 1));
    });
}

TEST(CrossOriginStorageRegistryGrease, NeverGreasesAnEntryLargeEnoughToBeExpensiveToRefetch)
{
    // The specification forbids GREASE'ing where a spurious re-download would be
    // disproportionate. This has to hold on every roll, not merely usually, so
    // the assertion is over many trials rather than one.
    for (unsigned i = 0; i < 5000; ++i) {
        EXPECT_FALSE(WebKit::CrossOriginStorageRegistry::shouldGreaseForTesting(greaseSizeCeiling));
        EXPECT_FALSE(WebKit::CrossOriginStorageRegistry::shouldGreaseForTesting(greaseSizeCeiling * 4));
    }
}

TEST(CrossOriginStorageRegistryGrease, SometimesGreasesASmallEntry)
{
    // Asserts the shape, not a rate: GREASE'ing that never fires provides no
    // cover at all, and pinning the probability would just restate the constant.
    // With the shipped probability, the chance of seeing none of these fire is
    // vanishingly small -- but not zero, which is why this asserts "at least
    // one" rather than a count.
    unsigned greased = 0;
    for (unsigned i = 0; i < 20000; ++i) {
        if (WebKit::CrossOriginStorageRegistry::shouldGreaseForTesting(1024))
            ++greased;
    }
    EXPECT_GT(greased, 0u);
    // ...and it must not be greasing everything either, which would break the
    // feature while still passing the assertion above.
    EXPECT_LT(greased, 20000u);
}

} // namespace TestWebKitAPI
