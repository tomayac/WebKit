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

#include <wtf/CrossThreadCopier.h>
#include <wtf/Vector.h>
#include <wtf/text/WTFString.h>

namespace WebCore {

// https://wicg.github.io/cross-origin-storage/#cos-entries
// The "origins" item of a COS entry: the declared sharing scope of an entry.
enum class CrossOriginStorageOriginsScope : uint8_t {
    // options.origins was omitted: same-site origins only.
    SameSite,
    // options.origins was a string or a sequence of origin strings: only those origins.
    List,
    // options.origins was "*": any origin, subject to availability gating.
    Wildcard,
};

// A validated, normalized requestFileHandle() request, as sent to the COS registry.
// https://wicg.github.io/cross-origin-storage/#validate-a-cos-request
// https://wicg.github.io/cross-origin-storage/#normalize-requested-origins
struct CrossOriginStorageRequestData {
    // COS hash: a WebCrypto hash algorithm name, and a lowercase hex digest.
    String algorithm;
    String value;
    bool create { false };
    CrossOriginStorageOriginsScope originsScope { CrossOriginStorageOriginsScope::SameSite };
    // Serialized origins, deduplicated. Only non-empty when originsScope is List.
    Vector<String> origins;

    CrossOriginStorageRequestData isolatedCopy() const & { return { algorithm.isolatedCopy(), value.isolatedCopy(), create, originsScope, crossThreadCopy(origins) }; }
    CrossOriginStorageRequestData isolatedCopy() && { return { WTF::move(algorithm).isolatedCopy(), WTF::move(value).isolatedCopy(), create, originsScope, crossThreadCopy(WTF::move(origins)) }; }
};

// The hash algorithms recognized by the Web Cryptography API, with the hex length of each one's
// digest.
//
// A COS hash value ends up as a component of an on-disk path in the network process, so the shape
// of *every* recognized algorithm's value is validated, not just SHA-256's, which is the only one
// the specification normatively constrains. Validating only the algorithm a test suite happens to
// exercise leaves the others as a path traversal vector.
struct CrossOriginStorageHashAlgorithm {
    ASCIILiteral name;
    unsigned hexDigestLength;
};

inline constexpr std::array crossOriginStorageHashAlgorithms {
    CrossOriginStorageHashAlgorithm { "SHA-1"_s, 40 },
    CrossOriginStorageHashAlgorithm { "SHA-256"_s, 64 },
    CrossOriginStorageHashAlgorithm { "SHA-384"_s, 96 },
    CrossOriginStorageHashAlgorithm { "SHA-512"_s, 128 },
};

inline const CrossOriginStorageHashAlgorithm* findCrossOriginStorageHashAlgorithm(StringView name)
{
    for (auto& algorithm : crossOriginStorageHashAlgorithms) {
        if (equalIgnoringASCIICase(name, algorithm.name))
            return &algorithm;
    }
    return nullptr;
}

inline bool isValidCrossOriginStorageHashValue(StringView value, unsigned expectedLength)
{
    if (value.length() != expectedLength)
        return false;

    for (unsigned index = 0; index < expectedLength; ++index) {
        auto character = value[index];
        bool isLowercaseHexDigit = isASCIIDigit(character) || (character >= 'a' && character <= 'f');
        if (!isLowercaseHexDigit)
            return false;
    }

    return true;
}

// Used on both sides of the process boundary: once in the script-facing validation that turns a
// malformed request into a TypeError, and again on the trusted side, which must not assume a
// message reaching it already passed validation somewhere upstream.
inline bool isValidCrossOriginStorageHash(StringView algorithm, StringView value)
{
    auto* recognized = findCrossOriginStorageHashAlgorithm(algorithm);
    return recognized && isValidCrossOriginStorageHashValue(value, recognized->hexDigestLength);
}

} // namespace WebCore
