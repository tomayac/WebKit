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

#include <wtf/ExportMacros.h>
#include <wtf/Forward.h>
#include <wtf/Lock.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/Vector.h>
#include <wtf/text/WTFString.h>

namespace WebKit {

// The Public Hash List: the gate that makes "*"-scoped disclosure safe.
//
// Without it, "*" would be a trivial cross-site probing oracle: a site could write
// sha256(some-value-only-known-if-you-visited-site-B), globally scoped, and later probe for that
// exact hash from an unrelated context to learn whether the user visited site B. A "*"-scoped
// entry is therefore only disclosed outside its storing origins if its hash is independently
// confirmed present on this curated, cross-vendor, rolling-release allowlist of ubiquitous,
// corroborated digests. A hash that is not on the list fails closed: it is simply not disclosed,
// indistinguishable from a genuine miss.
//
// The list is shipped as a plain external data file next to the built framework rather than
// compiled in: at real scale it is roughly 295,000 entries, and at 32 bytes each that is a
// multi-megabyte resource this translation unit has no reason to own. It is loaded lazily, once,
// on the first lookup, and any read failure fails safe to an empty list, which behaves exactly
// like a genuinely empty list rather than like "everything is allowed".
//
// The published list only carries SHA-256 digests, so a "*"-scoped entry hashed with any other
// recognized algorithm can never clear this gate; the algorithm is checked before the lookup.
class CrossOriginStoragePublicHashList {
public:
    WTF_EXPORT_DECLARATION static CrossOriginStoragePublicHashList& singleton();

    // |algorithm| is a recognized WebCrypto hash algorithm name; |hexValue| is its lowercase hex
    // digest, already validated for shape.
    WTF_EXPORT_DECLARATION bool contains(const String& algorithm, const String& hexValue);

    // Testing hooks: the shipped list intentionally cannot be enumerated or synthesized from
    // web content, so a test needs a way to substitute a known snapshot.
    WTF_EXPORT_DECLARATION void setDataPathForTesting(const String&);
    WTF_EXPORT_DECLARATION void clearForTesting();

    WTF_EXPORT_DECLARATION size_t sizeForTesting();

private:
    friend class WTF::NeverDestroyed<CrossOriginStoragePublicHashList>;

    CrossOriginStoragePublicHashList() = default;

    void loadIfNeeded() WTF_REQUIRES_LOCK(m_lock);
    static String defaultDataPath();

    Lock m_lock;
    bool m_loaded WTF_GUARDED_BY_LOCK(m_lock) { false };
    String m_dataPathOverride WTF_GUARDED_BY_LOCK(m_lock);
    // Sorted, packed, 32-byte digests with no delimiters, so that a lookup is an O(log n) binary
    // search over a read-only array rather than a hash set of hundreds of thousands of entries.
    // Sorting happens once, at list-generation time, so nothing re-sorts it at startup.
    Vector<uint8_t> m_packedDigests WTF_GUARDED_BY_LOCK(m_lock);
};

} // namespace WebKit
