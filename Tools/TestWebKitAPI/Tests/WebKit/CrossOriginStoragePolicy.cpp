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

#include "Helpers/Test.h"
#include <limits>
#include <wtf/HexNumber.h>
#include <wtf/text/MakeString.h>
#include <wtf/text/StringBuilder.h>

namespace TestWebKitAPI {

using namespace WebKit::CrossOriginStoragePolicy;
using namespace WebCore::CrossOriginStorageLimits;
using Scope = WebCore::CrossOriginStorageOriginsScope;

// A syntactically valid, distinct SHA-256 value. Nothing here validates the shape, but using
// realistic values keeps a failure message readable as the thing it represents.
static String hashValue(unsigned seed)
{
    StringBuilder builder;
    builder.append(hex(seed, 8, Lowercase));
    while (builder.length() < 64)
        builder.append('0');
    return builder.toString();
}

// MARK: - On-disk metadata record

TEST(CrossOriginStoragePolicy, RecordRoundTripsEveryPersistedField)
{
    EntryRecord written;
    written.algorithm = "SHA-256"_s;
    written.value = hashValue(1);
    written.size = 4096;
    // Truncated to milliseconds, which is the format's resolution: comparing against
    // WallTime::now() directly would compare a value the format cannot represent.
    written.lastReadTime = WallTime::fromRawSeconds(1755000000.5);
    written.originsScope = Scope::List;
    written.attributedOrigin = "https://storer.example"_s;
    written.origins = { "https://a.example"_s, "https://b.example"_s };
    written.storingOrigins = { "https://storer.example"_s, "https://other.example"_s };

    auto read = EntryRecord::parse(written.serialize());
    ASSERT_TRUE(!!read);
    EXPECT_STREQ(read->algorithm.utf8().data(), "SHA-256");
    EXPECT_STREQ(read->value.utf8().data(), written.value.utf8().data());
    EXPECT_EQ(read->size, 4096u);
    EXPECT_EQ(read->lastReadTime.secondsSinceEpoch().milliseconds(), written.lastReadTime.secondsSinceEpoch().milliseconds());
    EXPECT_TRUE(read->originsScope == Scope::List);
    EXPECT_STREQ(read->attributedOrigin.utf8().data(), "https://storer.example");
    ASSERT_EQ(read->origins.size(), 2u);
    EXPECT_STREQ(read->origins[1].utf8().data(), "https://b.example");
    ASSERT_EQ(read->storingOrigins.size(), 2u);
    EXPECT_STREQ(read->storingOrigins[1].utf8().data(), "https://other.example");
}

TEST(CrossOriginStoragePolicy, RecordRoundTripsAnEmptyAttributedOrigin)
{
    // The regression this format is easiest to get wrong on. The attributed origin is empty for an
    // entry nobody is charged for, and because the format is positional, dropping the empty line
    // shifts every field after it up by one -- so the origins-list *count* would be read out of
    // the attributed-origin slot and the entry would come back structurally intact but wrong,
    // rather than failing loudly.
    EntryRecord written;
    written.algorithm = "SHA-256"_s;
    written.value = hashValue(2);
    written.size = 64;
    written.attributedOrigin = emptyString();
    written.origins = { "https://a.example"_s };
    written.storingOrigins = { "https://b.example"_s };

    auto read = EntryRecord::parse(written.serialize());
    ASSERT_TRUE(!!read);
    EXPECT_TRUE(read->attributedOrigin.isEmpty());
    EXPECT_EQ(read->size, 64u);
    ASSERT_EQ(read->origins.size(), 1u);
    EXPECT_STREQ(read->origins[0].utf8().data(), "https://a.example");
    ASSERT_EQ(read->storingOrigins.size(), 1u);
    EXPECT_STREQ(read->storingOrigins[0].utf8().data(), "https://b.example");
}

TEST(CrossOriginStoragePolicy, RecordRejectsAnUnrecognizedFormatVersion)
{
    EntryRecord written;
    written.algorithm = "SHA-256"_s;
    written.value = hashValue(3);
    auto serialized = written.serialize();

    // A record from a future WebKit must be discarded rather than reinterpreted under this
    // version's field order, which would silently produce a wrong entry.
    EXPECT_FALSE(!!EntryRecord::parse(makeString("99\n"_s, serialized.substring(serialized.find('\n') + 1))));
    EXPECT_FALSE(!!EntryRecord::parse("not-a-version\nSHA-256\n"_s));
    EXPECT_FALSE(!!EntryRecord::parse(emptyString()));
}

TEST(CrossOriginStoragePolicy, RecordRejectsADisclosureScopeOutsideTheEnum)
{
    // Reached by a corrupted or hand-edited file. Casting an out-of-range value into the enum
    // would be undefined behaviour, and the value decides who may read the entry, so it is
    // checked before the cast rather than clamped after it.
    EntryRecord written;
    written.algorithm = "SHA-256"_s;
    written.value = hashValue(4);
    auto lines = written.serialize().split('\n');
    lines[5] = "7"_s;

    StringBuilder builder;
    for (auto& line : lines)
        builder.append(line, '\n');
    EXPECT_FALSE(!!EntryRecord::parse(builder.toString()));
}

TEST(CrossOriginStoragePolicy, RecordTruncatesAnOverLongOriginsList)
{
    // The count is read from the file, so a corrupted or hostile one can claim any length. It
    // bounds a loop that appends, so it is clamped to the same maximum the API enforces rather
    // than trusted.
    StringBuilder builder;
    builder.append(EntryRecord::formatVersion, '\n');
    builder.append("SHA-256\n"_s);
    builder.append(hashValue(5), '\n');
    builder.append("128\n0\n0\n"_s);
    builder.append("https://storer.example\n"_s);
    builder.append(maximumOriginsListLength + 50, '\n');
    for (size_t index = 0; index < maximumOriginsListLength + 50; ++index)
        builder.append("https://origin-"_s, index, ".example\n"_s);
    builder.append("0\n"_s);

    auto read = EntryRecord::parse(builder.toString());
    ASSERT_TRUE(!!read);
    EXPECT_EQ(read->origins.size(), maximumOriginsListLength);
}

TEST(CrossOriginStoragePolicy, RecordSurvivesATruncatedFile)
{
    // A file cut short by a full disk or a crash mid-write. Every field past the cut reads as
    // absent, which the registry then rejects by cross-checking against the bytes file -- the
    // point here is only that parsing does not read past the end.
    EntryRecord written;
    written.algorithm = "SHA-256"_s;
    written.value = hashValue(6);
    written.size = 999;
    written.origins = { "https://a.example"_s, "https://b.example"_s };

    auto serialized = written.serialize();
    auto read = EntryRecord::parse(serialized.left(serialized.length() / 2));
    ASSERT_TRUE(!!read);
    EXPECT_TRUE(read->storingOrigins.isEmpty());
}

// MARK: - GREASE'ing

TEST(CrossOriginStoragePolicy, NeverGreasesAtOrAboveTheSizeCeiling)
{
    // Deterministic, unlike the roll below: at or above the ceiling the answer is always no, so a
    // single true here is a real failure rather than an unlucky sample.
    for (unsigned attempt = 0; attempt < 10000; ++attempt) {
        EXPECT_FALSE(shouldGrease(greaseSizeCeiling));
        EXPECT_FALSE(shouldGrease(greaseSizeCeiling + 1));
        EXPECT_FALSE(shouldGrease(4ULL * 1024 * MB));
    }
}

TEST(CrossOriginStoragePolicy, GreasesSmallEntriesAtRoughlyTheConfiguredRate)
{
    // A rate test, not an exact one: the roll is cryptographically random by design. The bounds
    // are wide enough (~15 standard deviations at this sample size) that a passing implementation
    // will not trip them, while still catching the failures that matter -- never GREASE'ing at
    // all, GREASE'ing everything, or being off by an order of magnitude.
    static constexpr unsigned attempts = 100000;
    unsigned greased = 0;
    for (unsigned attempt = 0; attempt < attempts; ++attempt) {
        if (shouldGrease(greaseSizeCeiling - 1))
            ++greased;
    }

    EXPECT_GT(greased, static_cast<unsigned>(attempts * greaseProbability / 2));
    EXPECT_LT(greased, static_cast<unsigned>(attempts * greaseProbability * 2));
}

// MARK: - Storage budget

TEST(CrossOriginStoragePolicy, DerivesTheBudgetFromTotalCapacityAndClampsIt)
{
    EXPECT_EQ(globalBudgetForVolumeCapacity(0), 0u);
    EXPECT_EQ(globalBudgetForVolumeCapacity(1000), static_cast<uint64_t>(1000 * globalBudgetDiskCapacityRatio));

    // The ceiling exists to contain a platform API that misreports capacity, so it must bind
    // independently of the percentage rather than merely scaling with it.
    EXPECT_EQ(globalBudgetForVolumeCapacity(std::numeric_limits<uint64_t>::max() / 2), globalBudgetCeiling);
    EXPECT_EQ(perOriginBudgetForGlobalBudget(1000), static_cast<uint64_t>(1000 * perOriginBudgetRatio));
}

// MARK: - Eviction

static EvictionCandidate candidate(const char* key, double lastReadSeconds, uint64_t size, const String& origin, bool shared = false)
{
    return {
        String::fromLatin1(key),
        WallTime::fromRawSeconds(lastReadSeconds),
        size,
        origin,
        shared ? String { } : origin,
    };
}

TEST(CrossOriginStoragePolicy, RejectsAWriteNoAmountOfEvictionCouldFit)
{
    BudgetState state { 0, 0, 1000, 200 };
    // Larger than the per-origin share, and separately larger than the whole budget. Neither can
    // be helped by evicting anything, so nothing is evicted on the way to saying no.
    auto plan = planEviction({ }, "https://a.example"_s, 500, state);
    EXPECT_FALSE(plan.fits);
    EXPECT_TRUE(plan.keysToEvict.isEmpty());

    EXPECT_FALSE(planEviction({ }, "https://a.example"_s, 2000, state).fits);
    // A capacity the platform could not report at all disables writing rather than defaulting to
    // something permissive.
    EXPECT_FALSE(planEviction({ }, "https://a.example"_s, 1, { 0, 0, 0, 0 }).fits);
}

TEST(CrossOriginStoragePolicy, EvictsAnOriginsOwnEntriesOldestReadFirst)
{
    auto origin = "https://a.example"_s;
    Vector<EvictionCandidate> candidates {
        candidate("newest", 300, 100, origin),
        candidate("oldest", 100, 100, origin),
        candidate("middle", 200, 100, origin),
    };

    // At its share with 300 stored, so exactly one entry has to go to fit another 100.
    auto plan = planEviction(candidates, origin, 100, { 300, 300, 10000, 300 });
    ASSERT_TRUE(plan.fits);
    ASSERT_EQ(plan.keysToEvict.size(), 1u);
    EXPECT_STREQ(plan.keysToEvict[0].utf8().data(), "oldest");
}

TEST(CrossOriginStoragePolicy, BreaksAReadTimeTieByKey)
{
    // Two entries read at the same instant must not evict in whichever order the registry's hash
    // map happened to iterate, or the same input would give different results run to run.
    auto origin = "https://a.example"_s;
    Vector<EvictionCandidate> candidates {
        candidate("zzz", 100, 100, origin),
        candidate("aaa", 100, 100, origin),
    };

    auto plan = planEviction(candidates, origin, 100, { 200, 200, 10000, 200 });
    ASSERT_TRUE(plan.fits);
    ASSERT_EQ(plan.keysToEvict.size(), 1u);
    EXPECT_STREQ(plan.keysToEvict[0].utf8().data(), "aaa");
}

TEST(CrossOriginStoragePolicy, OneOriginOverItsShareNeverEvictsAnothersEntries)
{
    // The property that keeps the per-origin share meaningful. Without it, an origin that writes
    // aggressively could push out a quieter origin's data simply by having read its own more
    // recently, which would make the share a suggestion rather than a floor.
    auto writer = "https://writer.example"_s;
    auto bystander = "https://bystander.example"_s;
    // The writer is at its share but has nothing evictable of its own -- its bytes are in an entry
    // with a writer still outstanding, which the registry filters out before planning. So the only
    // candidate on offer belongs to somebody else, and it is both older and larger, which is
    // exactly when taking it would be most tempting.
    Vector<EvictionCandidate> candidates {
        candidate("bystanders-old-entry", 100, 500, bystander),
    };

    // The global budget is nowhere near exhausted, so pass two never runs and cannot mask this.
    auto plan = planEviction(candidates, writer, 100, { 600, 100, 100000, 100 });
    EXPECT_FALSE(plan.fits);
    EXPECT_TRUE(plan.keysToEvict.isEmpty());
}

TEST(CrossOriginStoragePolicy, NeverReclaimsASharedEntryOnItsCoOwnersBehalf)
{
    // An origin over its share may reclaim only what it solely owns. A shared entry is another
    // origin's data too, and that origin may be well within its own share.
    auto writer = "https://writer.example"_s;
    Vector<EvictionCandidate> candidates {
        candidate("shared-with-another-origin", 100, 200, writer, /* shared */ true),
    };

    auto plan = planEviction(candidates, writer, 100, { 200, 200, 100000, 200 });
    EXPECT_FALSE(plan.fits);
    EXPECT_TRUE(plan.keysToEvict.isEmpty());
}

TEST(CrossOriginStoragePolicy, FallsBackToCrossOriginLRUOnlyWhenTheGlobalCapIsHit)
{
    // Pass two. Every origin here is within its own share, so no one origin is to blame; the
    // shortfall is genuine multi-tenant demand, and plain LRU across everyone is the fair answer.
    Vector<EvictionCandidate> candidates {
        candidate("a-oldest", 100, 400, "https://a.example"_s),
        candidate("b-newer", 500, 400, "https://b.example"_s),
    };

    auto plan = planEviction(candidates, "https://c.example"_s, 400, { 800, 0, 1000, 500 });
    ASSERT_TRUE(plan.fits);
    ASSERT_EQ(plan.keysToEvict.size(), 1u);
    // Another origin's entry, which pass one would never have touched.
    EXPECT_STREQ(plan.keysToEvict[0].utf8().data(), "a-oldest");
}

TEST(CrossOriginStoragePolicy, DoesNotEvictWhenTheWriteAlreadyFits)
{
    Vector<EvictionCandidate> candidates {
        candidate("untouched", 100, 100, "https://a.example"_s),
    };

    auto plan = planEviction(candidates, "https://a.example"_s, 100, { 100, 100, 10000, 1000 });
    EXPECT_TRUE(plan.fits);
    EXPECT_TRUE(plan.keysToEvict.isEmpty());
}

TEST(CrossOriginStoragePolicy, CountsAnEntryOnceWhenBothPassesWouldEvictIt)
{
    // An entry evicted to get the writer back under its own share has already given its bytes
    // back to the global total. Listing it again in pass two would double-count the space and let
    // through a write that does not actually fit.
    auto writer = "https://writer.example"_s;
    Vector<EvictionCandidate> candidates {
        candidate("writers-only-entry", 100, 400, writer),
    };

    auto plan = planEviction(candidates, writer, 400, { 400, 400, 500, 400 });
    ASSERT_TRUE(plan.fits);
    EXPECT_EQ(plan.keysToEvict.size(), 1u);
}

} // namespace TestWebKitAPI
