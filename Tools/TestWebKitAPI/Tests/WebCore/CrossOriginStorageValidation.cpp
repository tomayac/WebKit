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

#include "Helpers/Test.h"
#include <WebCore/CrossOriginStorageLimits.h>
#include <WebCore/CrossOriginStorageManager.h>
#include <WebCore/ExceptionOr.h>
#include <wtf/MainThread.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/text/MakeString.h>
#include <wtf/text/StringBuilder.h>

namespace TestWebKitAPI {

using namespace WebCore;
using Hash = CrossOriginStorageManager::RequestFileHandleHash;
using Options = CrossOriginStorageManager::RequestFileHandleOptions;

class CrossOriginStorageValidationTest : public testing::Test {
public:
    void SetUp() final
    {
        WTF::initializeMainThread();
    }
};

static Hash sha256(const String& value)
{
    return Hash { value, "SHA-256"_s };
}

static const String& validSHA256()
{
    static NeverDestroyed<String> value { "6d567d7c2f46febcdeaf874614d63e3192ff3a844ee34f8bb63f4c5cf259f233"_s };
    return value;
}

// A syntactically valid lowercase-hex digest of the requested length.
static String hexOfLength(unsigned length)
{
    StringBuilder builder;
    for (unsigned index = 0; index < length; ++index)
        builder.append('a');
    return builder.toString();
}

TEST_F(CrossOriginStorageValidationTest, RejectsAlgorithmsWebCryptoDoesNotRecognize)
{
    EXPECT_TRUE(CrossOriginStorageManager::validateAndNormalize(Hash { validSHA256(), "md5"_s }, { }).hasException());
    EXPECT_TRUE(CrossOriginStorageManager::validateAndNormalize(Hash { validSHA256(), "not-a-real-algorithm"_s }, { }).hasException());
}

TEST_F(CrossOriginStorageValidationTest, NormalizesAlgorithmNameCase)
{
    // Two requests differing only in the case of the algorithm name must address the same entry,
    // so the name is canonicalized here rather than compared case-insensitively at every use.
    auto result = CrossOriginStorageManager::validateAndNormalize(Hash { validSHA256(), "sha-256"_s }, { });
    ASSERT_FALSE(result.hasException());
    EXPECT_STREQ(result.returnValue().algorithm.utf8().data(), "SHA-256");
}

TEST_F(CrossOriginStorageValidationTest, RejectsMalformedHashValues)
{
    EXPECT_TRUE(CrossOriginStorageManager::validateAndNormalize(sha256(hexOfLength(63)), { }).hasException());
    EXPECT_TRUE(CrossOriginStorageManager::validateAndNormalize(sha256(hexOfLength(65)), { }).hasException());
    // Uppercase is not accepted: the value is normatively lowercase, so comparison stays a plain
    // string comparison rather than a case-insensitive one.
    EXPECT_TRUE(CrossOriginStorageManager::validateAndNormalize(sha256(validSHA256().convertToASCIIUppercase()), { }).hasException());
    EXPECT_TRUE(CrossOriginStorageManager::validateAndNormalize(sha256("not-hexadecimal-not-hexadecimal-not-hexadecimal-not-hexadecimal-"_s), { }).hasException());
}

TEST_F(CrossOriginStorageValidationTest, ValidatesDigestLengthForEveryRecognizedAlgorithm)
{
    // The specification only constrains SHA-256's value shape, but this value becomes a component
    // of an on-disk path in the network process, so validating only the algorithm the test suite
    // happens to exercise would leave the others as a path traversal vector.
    auto sha256Length = validSHA256();
    EXPECT_TRUE(CrossOriginStorageManager::validateAndNormalize(Hash { sha256Length, "SHA-1"_s }, { }).hasException());
    EXPECT_TRUE(CrossOriginStorageManager::validateAndNormalize(Hash { sha256Length, "SHA-384"_s }, { }).hasException());
    EXPECT_TRUE(CrossOriginStorageManager::validateAndNormalize(Hash { sha256Length, "SHA-512"_s }, { }).hasException());

    // ...and the correctly-sized value for each of them is accepted.
    EXPECT_FALSE(CrossOriginStorageManager::validateAndNormalize(Hash { hexOfLength(40), "SHA-1"_s }, { }).hasException());
    EXPECT_FALSE(CrossOriginStorageManager::validateAndNormalize(Hash { hexOfLength(96), "SHA-384"_s }, { }).hasException());
    EXPECT_FALSE(CrossOriginStorageManager::validateAndNormalize(Hash { hexOfLength(128), "SHA-512"_s }, { }).hasException());
}

TEST_F(CrossOriginStorageValidationTest, RejectsAPathTraversalAttemptDisguisedAsALongDigest)
{
    // The concrete shape of the bug the per-algorithm check closes. Deliberately exactly as long
    // as a SHA-512 digest, so that it is the hex-charset check doing the rejecting rather than the
    // length check: a value that merely happened to be the wrong length would prove nothing.
    StringBuilder builder;
    while (builder.length() < 128 - 5)
        builder.append("../"_s);
    builder.append("etc/x"_s);
    auto traversal = builder.toString();
    ASSERT_EQ(traversal.length(), 128u);
    EXPECT_TRUE(CrossOriginStorageManager::validateAndNormalize(Hash { traversal, "SHA-512"_s }, { }).hasException());
}

TEST_F(CrossOriginStorageValidationTest, TreatsWildcardAsItsOwnScope)
{
    Options options;
    options.origins = Variant<String, Vector<String>> { "*"_s };
    auto result = CrossOriginStorageManager::validateAndNormalize(sha256(validSHA256()), options);
    ASSERT_FALSE(result.hasException());
    EXPECT_TRUE(result.returnValue().originsScope == CrossOriginStorageOriginsScope::Wildcard);
    EXPECT_TRUE(result.returnValue().origins.isEmpty());
}

TEST_F(CrossOriginStorageValidationTest, DefaultsToSameSiteWhenOriginsIsOmitted)
{
    auto result = CrossOriginStorageManager::validateAndNormalize(sha256(validSHA256()), { });
    ASSERT_FALSE(result.hasException());
    EXPECT_TRUE(result.returnValue().originsScope == CrossOriginStorageOriginsScope::SameSite);
}

TEST_F(CrossOriginStorageValidationTest, RejectsUnparsableAndOpaqueOrigins)
{
    Options unparsable;
    unparsable.origins = Variant<String, Vector<String>> { "not a url"_s };
    EXPECT_TRUE(CrossOriginStorageManager::validateAndNormalize(sha256(validSHA256()), unparsable).hasException());

    Options opaque;
    opaque.origins = Variant<String, Vector<String>> { Vector<String> { "data:text/plain,hi"_s } };
    EXPECT_TRUE(CrossOriginStorageManager::validateAndNormalize(sha256(validSHA256()), opaque).hasException());

    Options oneBad;
    oneBad.origins = Variant<String, Vector<String>> { Vector<String> { "https://valid.example"_s, "not a url"_s } };
    EXPECT_TRUE(CrossOriginStorageManager::validateAndNormalize(sha256(validSHA256()), oneBad).hasException());
}

TEST_F(CrossOriginStorageValidationTest, RejectsAnOverLongOriginsList)
{
    // A single call that exceeds the maximum is an immediate TypeError, before anything is fetched,
    // hashed, or written. This is the half of the limit that a caller can be blamed for; the merge
    // path silently truncates instead.
    Vector<String> origins;
    for (size_t index = 0; index <= CrossOriginStorageLimits::maximumOriginsListLength; ++index)
        origins.append(makeString("https://origin-"_s, index, ".example"_s));

    Options options;
    options.origins = Variant<String, Vector<String>> { origins };
    EXPECT_TRUE(CrossOriginStorageManager::validateAndNormalize(sha256(validSHA256()), options).hasException());
}

TEST_F(CrossOriginStorageValidationTest, DeduplicatesAndSerializesTheOriginsList)
{
    // Deduplicating here, rather than only when merging into an existing entry, keeps an entry's
    // origins list duplicate-free from the moment it is created.
    Options options;
    options.origins = Variant<String, Vector<String>> { Vector<String> {
        "https://a.example/some/path"_s,
        "https://a.example"_s,
        "https://b.example:443"_s,
    } };

    auto result = CrossOriginStorageManager::validateAndNormalize(sha256(validSHA256()), options);
    ASSERT_FALSE(result.hasException());

    auto& normalized = result.returnValue().origins;
    EXPECT_TRUE(result.returnValue().originsScope == CrossOriginStorageOriginsScope::List);
    ASSERT_EQ(normalized.size(), 2u);
    EXPECT_STREQ(normalized[0].utf8().data(), "https://a.example");
    // The default port is dropped by origin serialization, so this is the same origin either way.
    EXPECT_STREQ(normalized[1].utf8().data(), "https://b.example");
}

} // namespace TestWebKitAPI
