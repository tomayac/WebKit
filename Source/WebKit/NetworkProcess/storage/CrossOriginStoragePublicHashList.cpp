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

#include <cstdlib>
#include <wtf/ASCIICType.h>
#include <wtf/FileSystem.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/text/StringToIntegerConversion.h>

#if PLATFORM(COCOA)
#include <CoreFoundation/CoreFoundation.h>
#include <wtf/RetainPtr.h>
#endif

namespace WebKit {

// The published Public Hash List only carries SHA-256 digests.
static constexpr size_t digestSize = 32;
static constexpr ASCIILiteral supportedAlgorithm = "SHA-256"_s;
static constexpr ASCIILiteral dataFileName = "CrossOriginStoragePublicHashList.dat"_s;

CrossOriginStoragePublicHashList& CrossOriginStoragePublicHashList::singleton()
{
    static NeverDestroyed<CrossOriginStoragePublicHashList> list;
    return list.get();
}

String CrossOriginStoragePublicHashList::defaultDataPath()
{
    // An explicit override exists so that a development build, or a test that needs a known
    // snapshot, can point at a specific list without reinstalling the framework.
    if (auto* path = getenv("WEBKIT_CROSS_ORIGIN_STORAGE_PUBLIC_HASH_LIST"))
        return String::fromUTF8(path);

#if PLATFORM(COCOA)
    // Resolved relative to the installed framework's own resources: this is compiled-application
    // data shipped alongside the binary, not per-user state in a profile directory.
    if (auto* bundle = CFBundleGetBundleWithIdentifier(CFSTR("com.apple.WebKit"))) {
        RetainPtr<CFStringRef> fileName = adoptCF(CFStringCreateWithCString(kCFAllocatorDefault, dataFileName.characters(), kCFStringEncodingUTF8));
        RetainPtr<CFURLRef> url = adoptCF(CFBundleCopyResourceURL(bundle, fileName.get(), nullptr, nullptr));
        if (url) {
            RetainPtr<CFStringRef> path = adoptCF(CFURLCopyFileSystemPath(url.get(), kCFURLPOSIXPathStyle));
            if (path)
                return path.get();
        }
    }
#elif defined(WEBKIT_CROSS_ORIGIN_STORAGE_PUBLIC_HASH_LIST_PATH)
    return String::fromUTF8(WEBKIT_CROSS_ORIGIN_STORAGE_PUBLIC_HASH_LIST_PATH);
#endif

    return { };
}

void CrossOriginStoragePublicHashList::loadIfNeeded()
{
    if (m_loaded)
        return;

    // Set first: a failed load must not be retried on every single lookup, and must leave the
    // list empty rather than in any state that could read as "everything is on the list".
    m_loaded = true;

    auto path = m_dataPathOverride.isEmpty() ? defaultDataPath() : m_dataPathOverride;
    if (path.isEmpty())
        return;

    auto contents = FileSystem::readEntireFile(path);
    if (!contents)
        return;

    // A file whose length is not a whole number of digests is corrupt; fail safe to empty rather
    // than to a partially-parsed list.
    if (contents->size() % digestSize)
        return;

    m_packedDigests = WTF::move(*contents);
}

static std::optional<std::array<uint8_t, digestSize>> parseHexDigest(const String& hexValue)
{
    if (hexValue.length() != digestSize * 2)
        return std::nullopt;

    std::array<uint8_t, digestSize> digest;
    for (size_t index = 0; index < digestSize; ++index) {
        auto high = toASCIIHexValue(hexValue[index * 2]);
        auto low = toASCIIHexValue(hexValue[index * 2 + 1]);
        if (!isASCIIHexDigit(hexValue[index * 2]) || !isASCIIHexDigit(hexValue[index * 2 + 1]))
            return std::nullopt;
        digest[index] = static_cast<uint8_t>((high << 4) | low);
    }

    return digest;
}

bool CrossOriginStoragePublicHashList::contains(const String& algorithm, const String& hexValue)
{
    if (!equalIgnoringASCIICase(algorithm, supportedAlgorithm))
        return false;

    auto digest = parseHexDigest(hexValue);
    if (!digest)
        return false;

    Locker locker { m_lock };
    loadIfNeeded();

    size_t count = m_packedDigests.size() / digestSize;
    if (!count)
        return false;

    auto data = m_packedDigests.span();
    auto target = std::span<const uint8_t> { *digest };
    size_t low = 0;
    size_t high = count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        auto candidate = data.subspan(middle * digestSize, digestSize);
        auto comparison = compareSpans(candidate, target);
        if (comparison == std::strong_ordering::equal)
            return true;
        if (comparison == std::strong_ordering::less)
            low = middle + 1;
        else
            high = middle;
    }

    return false;
}

void CrossOriginStoragePublicHashList::setDataPathForTesting(const String& path)
{
    Locker locker { m_lock };
    m_dataPathOverride = path;
    m_loaded = false;
    m_packedDigests.clear();
}

void CrossOriginStoragePublicHashList::clearForTesting()
{
    Locker locker { m_lock };
    m_dataPathOverride = { };
    m_loaded = false;
    m_packedDigests.clear();
}

size_t CrossOriginStoragePublicHashList::sizeForTesting()
{
    Locker locker { m_lock };
    loadIfNeeded();
    return m_packedDigests.size() / digestSize;
}

} // namespace WebKit
