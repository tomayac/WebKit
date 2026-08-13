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
#include "CrossOriginStoragePublicHashList.h"

#include "CrossOriginStoragePolicy.h"

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

    auto path = defaultDataPath();
    if (path.isEmpty())
        return;

    auto contents = FileSystem::readEntireFile(path);
    if (!contents)
        return;

    // A file whose length is not a whole number of digests is corrupt; fail safe to empty rather
    // than to a partially-parsed list.
    if (!CrossOriginStoragePolicy::PublicHashList::isWellFormedList(contents->size()))
        return;

    m_packedDigests = WTF::move(*contents);
}

bool CrossOriginStoragePublicHashList::contains(const String& algorithm, const String& hexValue)
{
    Locker locker { m_lock };
    loadIfNeeded();
    return CrossOriginStoragePolicy::PublicHashList::packedListContains(m_packedDigests.span(), algorithm, hexValue);
}

} // namespace WebKit
