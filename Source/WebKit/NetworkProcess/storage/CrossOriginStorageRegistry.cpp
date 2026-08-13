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
#include "CrossOriginStorageRegistry.h"

#include "CrossOriginStoragePolicy.h"
#include "CrossOriginStoragePublicHashList.h"
#include "FileSystemStorageHandle.h"
#include "FileSystemStorageHandleRegistry.h"
#include "FileSystemStorageManager.h"
#include <WebCore/CrossOriginStorageLimits.h>
#include <WebCore/FileSystemWriteCloseReason.h>
#include <WebCore/FileSystemWriteCommandType.h>
#include <WebCore/RegistrableDomain.h>
#include <pal/crypto/CryptoDigest.h>
#include <wtf/CheckedArithmetic.h>
#include <wtf/FileSystem.h>
#include <wtf/Function.h>
#include <wtf/HashSet.h>
#include <wtf/StdLibExtras.h>
#include <wtf/TZoneMallocInlines.h>
#include <wtf/URL.h>
#include <wtf/text/MakeString.h>
#include <wtf/text/StringToIntegerConversion.h>
#include <wtf/text/StringView.h>

namespace WebKit {

using namespace WebCore::CrossOriginStorageLimits;

WTF_MAKE_TZONE_ALLOCATED_IMPL(CrossOriginStorageRegistry);

static constexpr size_t hashReadChunkSize = 1 * MB;
static constexpr ASCIILiteral bytesDirectoryName = "files"_s;
static constexpr ASCIILiteral metadataDirectoryName = "metadata"_s;
static constexpr ASCIILiteral metadataFileExtension = ".meta"_s;
static constexpr ASCIILiteral temporaryFileExtension = ".tmp"_s;

Ref<CrossOriginStorageRegistry> CrossOriginStorageRegistry::create(String&& path, FileSystemStorageHandleRegistry& registry, std::optional<uint64_t> volumeCapacityOverride)
{
    return adoptRef(*new CrossOriginStorageRegistry(WTF::move(path), registry, volumeCapacityOverride));
}

CrossOriginStorageRegistry::CrossOriginStorageRegistry(String&& path, FileSystemStorageHandleRegistry& registry, std::optional<uint64_t> volumeCapacityOverride)
    : m_path(WTF::move(path))
    , m_handleRegistry(registry)
    , m_volumeCapacityOverride(volumeCapacityOverride)
{
    ASSERT(!RunLoop::isMain());

    // Created up front rather than on the first write, so that the storage budget -- which is a
    // fraction of the capacity of the volume this directory sits on -- can be computed at any
    // point without depending on whether some earlier operation happened to create it.
    FileSystem::makeAllDirectories(m_path);

    m_fileSystemStorageManager = FileSystemStorageManager::create(FileSystem::pathByAppendingComponent(m_path, bytesDirectoryName), registry, [weakThis = WeakPtr { *this }](uint64_t spaceRequested, CompletionHandler<void(bool)>&& completionHandler) {
        RefPtr protectedThis = weakThis.get();
        if (!protectedThis)
            return completionHandler(false);

        // A backstop only. The authoritative per-write bound is checkWriteCommand(), which runs
        // before the resize is attempted and knows which write session is asking; the real budget
        // check runs at close() time, once the bytes have actually been verified.
        auto budget = protectedThis->globalBudget();
        completionHandler(spaceRequested <= budget && protectedThis->m_totalBytes <= budget - spaceRequested);
    });

    loadEntriesFromDisk();
}

CrossOriginStorageRegistry::~CrossOriginStorageRegistry() = default;

String CrossOriginStorageRegistry::entryKey(const String& algorithm, const String& value)
{
    return makeString(algorithm, ':', value);
}

String CrossOriginStorageRegistry::bytesPath(const Entry& entry) const
{
    return FileSystem::pathByAppendingComponents(m_path, std::array<StringView, 3> { bytesDirectoryName, entry.algorithm, entry.value });
}

String CrossOriginStorageRegistry::metadataPath(const Entry& entry) const
{
    // Held in a local: a StringView into a makeString() temporary would dangle before the path is
    // built from it.
    auto fileName = makeString(entry.value, metadataFileExtension);
    return FileSystem::pathByAppendingComponents(m_path, std::array<StringView, 3> { metadataDirectoryName, entry.algorithm, fileName });
}

// Two origins are same site when their schemes match and they share a registrable domain, which
// is the same comparison the cookie jar already makes for SameSite. It is deliberately not
// same-origin: https://a.example.com and https://b.example.com are same site.
static bool isSameSite(const String& originA, const String& originB)
{
    if (originA == originB)
        return true;

    URL urlA { originA };
    URL urlB { originB };
    if (!urlA.isValid() || !urlB.isValid())
        return false;

    if (urlA.protocol() != urlB.protocol())
        return false;

    WebCore::RegistrableDomain domainA { urlA };
    WebCore::RegistrableDomain domainB { urlB };
    if (domainA.isEmpty() || domainB.isEmpty())
        return urlA.host() == urlB.host();

    return domainA == domainB;
}

CrossOriginStorageRegistry::Entry* CrossOriginStorageRegistry::findLiveEntry(const String& key)
{
    auto iterator = m_entries.find(key);
    if (iterator == m_entries.end())
        return nullptr;

    auto& entry = iterator->value;
    if (entry.state == Entry::State::Written)
        return &entry;

    // A pending entry can be abandoned outright: a page can navigate away, crash, or simply never
    // close its stream, in which case no message ever arrives to decrement anything. After the
    // staleness window it reads as absent, so a reader is not stuck behind a write that will never
    // finish, and a fresh create request for the same hash is not permanently blocked either.
    if (WallTime::now() - entry.createdTime <= pendingEntryStalenessTimeout)
        return &entry;

    removeEntry(key);
    return nullptr;
}

void CrossOriginStorageRegistry::removeEntry(const String& key)
{
    auto iterator = m_entries.find(key);
    if (iterator == m_entries.end())
        return;

    auto entry = m_entries.take(iterator);
    if (entry.state == Entry::State::Written)
        dischargeUsage(entry.attributedOrigin, entry.size);

    FileSystem::deleteFile(bytesPath(entry));
    FileSystem::deleteFile(metadataPath(entry));
}

// https://wicg.github.io/cross-origin-storage/#requestfilehandle
CrossOriginStorageRegistry::HandleResult CrossOriginStorageRegistry::requestFileHandle(IPC::Connection::UniqueID connection, const WebCore::ClientOrigin& clientOrigin, const WebCore::CrossOriginStorageRequestData& request)
{
    ASSERT(!RunLoop::isMain());

    auto requestingOrigin = clientOrigin.clientOrigin.toString();
    if (requestingOrigin.isEmpty() || requestingOrigin == "null"_s)
        return makeUnexpected(FileSystemStorageError::FileNotFound);

    if (request.create)
        return completeCreateRequest(connection, requestingOrigin, request);

    return completeReadRequest(connection, requestingOrigin, request);
}

// https://wicg.github.io/cross-origin-storage/#reading-files
CrossOriginStorageRegistry::HandleResult CrossOriginStorageRegistry::completeReadRequest(IPC::Connection::UniqueID connection, const String& requestingOrigin, const WebCore::CrossOriginStorageRequestData& request)
{
    // Being over budget must produce exactly what a genuine miss produces. A distinguishable
    // "rate limited" signal would make the limiter its own oracle.
    if (!m_rateLimiter.tryConsume(requestingOrigin, CrossOriginStorageRateLimiter::ProbeType::Read))
        return makeUnexpected(FileSystemStorageError::FileNotFound);

    auto key = entryKey(request.algorithm, request.value);
    auto* entry = findLiveEntry(key);
    if (!entry)
        return makeUnexpected(FileSystemStorageError::FileNotFound);

    // A hash with a write in progress deliberately does not behave like a hash that is absent, so
    // that a caller does not mistake it for a cache miss and start a redundant, concurrent
    // download of a very large file purely in order to write it.
    if (entry->state == Entry::State::Pending)
        return makeUnexpected(FileSystemStorageError::NotAllowed);

    if (!applyAvailabilityGating(*entry, requestingOrigin))
        return makeUnexpected(FileSystemStorageError::FileNotFound);

    auto path = bytesPath(*entry);
    if (!FileSystem::fileExists(path)) {
        // Metadata without bytes: degrade to absent rather than handing out a broken handle.
        removeEntry(key);
        return makeUnexpected(FileSystemStorageError::FileNotFound);
    }

    auto result = m_fileSystemStorageManager->createHandle(connection, FileSystemStorageHandle::Type::File, WTF::move(path), String { entry->value }, false);
    if (!result)
        return result;

    // Eviction is oldest-read-first, not oldest-written-first: an entry a writer keeps
    // re-verifying but nobody ever reads should go before one that is actively serving readers.
    entry->lastReadTime = WallTime::now();
    // A genuine read is also what refreshes a listed origin's recency, so that re-declaring an
    // origin in later writes cannot keep a dormant one alive.
    if (entry->originsScope == WebCore::CrossOriginStorageOriginsScope::List) {
        if (entry->origins.removeFirst(requestingOrigin))
            entry->origins.append(requestingOrigin);
    }
    persistEntry(*entry);

    m_handleContexts.add(result.value().second, HandleContext { key, requestingOrigin, false, WebCore::CrossOriginStorageOriginsScope::SameSite, { }, false });
    return result;
}

// https://wicg.github.io/cross-origin-storage/#creating-and-writing-files
CrossOriginStorageRegistry::HandleResult CrossOriginStorageRegistry::completeCreateRequest(IPC::Connection::UniqueID connection, const String& requestingOrigin, const WebCore::CrossOriginStorageRequestData& request)
{
    // A create request has no return value of its own, so it is not a fingerprinting oracle the
    // way a read is, but it is still real registry churn and disk I/O if flooded. Its budget is
    // shared with the write verification that follows it.
    if (!m_rateLimiter.tryConsume(requestingOrigin, CrossOriginStorageRateLimiter::ProbeType::Write))
        return makeUnexpected(FileSystemStorageError::QuotaError);

    auto key = entryKey(request.algorithm, request.value);
    auto* entry = findLiveEntry(key);
    if (!entry) {
        Entry newEntry;
        newEntry.algorithm = request.algorithm;
        newEntry.value = request.value;
        newEntry.state = Entry::State::Pending;
        newEntry.originsScope = request.originsScope;
        newEntry.origins = request.origins;
        newEntry.createdTime = WallTime::now();
        newEntry.lastReadTime = newEntry.createdTime;
        entry = &m_entries.add(key, WTF::move(newEntry)).iterator->value;
    }

    auto path = bytesPath(*entry);
    if (!FileSystem::fileExists(path)) {
        // The writable stream machinery accumulates into a sibling temporary file and only
        // publishes into this path on close, but it requires the destination to already exist.
        if (!FileSystem::makeAllDirectories(FileSystem::parentPath(path))) {
            if (entry->state == Entry::State::Pending && !entry->pendingWriterCount)
                m_entries.remove(key);
            return makeUnexpected(FileSystemStorageError::Unknown);
        }

        auto file = FileSystem::openFile(path, FileSystem::FileOpenMode::Truncate);
        if (!file) {
            if (entry->state == Entry::State::Pending && !entry->pendingWriterCount)
                m_entries.remove(key);
            return makeUnexpected(FileSystemStorageError::Unknown);
        }
    }

    auto result = m_fileSystemStorageManager->createHandle(connection, FileSystemStorageHandle::Type::File, WTF::move(path), String { entry->value }, true);
    if (!result) {
        if (entry->state == Entry::State::Pending && !entry->pendingWriterCount)
            removeEntry(key);
        return result;
    }

    // The handle counts as an outstanding writer even if the caller never calls createWritable()
    // on it, or never closes the resulting stream: an abandoned handle counts against the entry
    // exactly as an abandoned in-flight write already would, until the staleness timeout.
    ++entry->pendingWriterCount;

    // A handle is returned whether or not the entry already existed, and whether or not it is
    // already written: the caller still has to supply the complete bytes through it, so that a
    // create request cannot be used as an oracle for prior presence, and so that a request for a
    // more permissive origins value can be verified before being honored.
    m_handleContexts.add(result.value().second, HandleContext { key, requestingOrigin, true, request.originsScope, request.origins, true });
    return result;
}

// https://wicg.github.io/cross-origin-storage/#determine-cos-disclosure
bool CrossOriginStorageRegistry::determineDisclosure(const Entry& entry, const String& requestingOrigin)
{
    ASSERT(entry.state == Entry::State::Written);

    // An origin that has itself successfully written the entry can always read it back,
    // independent of the disclosure scope and independent of PHL membership. This mirrors the
    // Cache API's model, in which an origin always has access to what it stored.
    if (entry.storingOrigins.contains(requestingOrigin))
        return true;

    switch (entry.originsScope) {
    case WebCore::CrossOriginStorageOriginsScope::Wildcard:
        // The Public Hash List gate applies only here, to globally-scoped entries: the one case
        // where disclosure could otherwise reach any origin on the web. A hash that is not on the
        // list fails closed, indistinguishable from a genuine miss.
        return CrossOriginStoragePublicHashList::singleton().contains(entry.algorithm, entry.value);

    case WebCore::CrossOriginStorageOriginsScope::List:
        return entry.origins.contains(requestingOrigin);

    case WebCore::CrossOriginStorageOriginsScope::SameSite:
        for (auto& storingOrigin : entry.storingOrigins) {
            if (isSameSite(requestingOrigin, storingOrigin))
                return true;
        }
        return false;
    }

    ASSERT_NOT_REACHED();
    return false;
}

bool CrossOriginStorageRegistry::shouldGrease(const Entry& entry)
{
    return shouldGrease(entry.size);
}

bool CrossOriginStorageRegistry::shouldGrease(uint64_t entrySize)
{
    return CrossOriginStoragePolicy::shouldGrease(entrySize);
}

// https://wicg.github.io/cross-origin-storage/#apply-availability-gating
bool CrossOriginStorageRegistry::applyAvailabilityGating(Entry& entry, const String& requestingOrigin)
{
    if (!determineDisclosure(entry, requestingOrigin))
        return false;

    // A storing origin reading back its own write is never GREASEd: there is nothing to conceal
    // from it, and a false negative there would break the feature for its own writer.
    if (entry.storingOrigins.contains(requestingOrigin))
        return true;

    return !shouldGrease(entry);
}

// https://wicg.github.io/cross-origin-storage/#upgrade-resource-visibility
void CrossOriginStorageRegistry::upgradeResourceVisibility(Entry& entry, WebCore::CrossOriginStorageOriginsScope requestedScope, const Vector<String>& requestedOrigins)
{
    // Omitting origins never narrows an existing entry: it only requests same-site availability,
    // which every entry already has at least as much of.
    if (requestedScope == WebCore::CrossOriginStorageOriginsScope::SameSite)
        return;

    // An already-globally-available entry cannot be restricted by a later writer.
    if (entry.originsScope == WebCore::CrossOriginStorageOriginsScope::Wildcard)
        return;

    if (requestedScope == WebCore::CrossOriginStorageOriginsScope::Wildcard) {
        entry.originsScope = WebCore::CrossOriginStorageOriginsScope::Wildcard;
        entry.origins.clear();
        return;
    }

    if (entry.originsScope == WebCore::CrossOriginStorageOriginsScope::SameSite) {
        entry.originsScope = WebCore::CrossOriginStorageOriginsScope::List;
        entry.origins = requestedOrigins;
        entry.origins.shrink(std::min(entry.origins.size(), maximumOriginsListLength));
        return;
    }

    for (auto& candidate : requestedOrigins) {
        if (entry.origins.contains(candidate))
            continue;

        // The cumulative effect of independent writes can reach the cap with no misbehavior from
        // any single caller, and this write's bytes are already verified and stored. Dropping the
        // excess origins is therefore the right outcome; failing the write is not.
        if (entry.origins.size() >= maximumOriginsListLength)
            break;

        entry.origins.append(candidate);
    }
}

bool CrossOriginStorageRegistry::ownsHandle(WebCore::FileSystemHandleIdentifier identifier) const
{
    return m_handleContexts.contains(identifier);
}

std::optional<FileSystemStorageError> CrossOriginStorageRegistry::prepareGetFile(WebCore::FileSystemHandleIdentifier identifier)
{
    auto iterator = m_handleContexts.find(identifier);
    if (iterator == m_handleContexts.end())
        return FileSystemStorageError::Unknown;

    auto* entry = findLiveEntry(iterator->value.entryKey);
    if (!entry)
        return FileSystemStorageError::FileNotFound;

    // Even the caller that requested the handle must not observe a not-yet-verified placeholder
    // as if it were the file's real contents.
    if (entry->state == Entry::State::Pending)
        return FileSystemStorageError::NotAllowed;

    entry->lastReadTime = WallTime::now();
    persistEntry(*entry);
    return std::nullopt;
}

std::optional<FileSystemStorageError> CrossOriginStorageRegistry::checkWriteCommand(WebCore::FileSystemHandleIdentifier identifier, WebCore::FileSystemWritableFileStreamIdentifier streamIdentifier, WebCore::FileSystemWriteCommandType type, std::optional<uint64_t> position, std::optional<uint64_t> size, size_t dataSize)
{
    if (!m_handleContexts.contains(identifier))
        return FileSystemStorageError::Unknown;

    auto session = m_writeSessions.get(streamIdentifier);

    switch (type) {
    case WebCore::FileSystemWriteCommandType::Truncate:
        // Nothing crosses the wire for a truncate, so without this the real budget check at
        // close() could be preceded by an arbitrarily large claim on disk.
        session.size = size.value_or(0);
        session.position = std::min(session.position, session.size);
        break;

    case WebCore::FileSystemWriteCommandType::Write: {
        // An unpositioned write continues from the stream's current position, which a preceding
        // seek() may have moved far past the end of the file. Falling back to the current size
        // instead would let seek(huge) + write(oneByte) slip under the cap.
        CheckedUint64 end = position.value_or(session.position);
        end += dataSize;
        if (end.hasOverflowed())
            return FileSystemStorageError::QuotaError;
        session.position = end;
        session.size = std::max<uint64_t>(session.size, end);
        break;
    }

    case WebCore::FileSystemWriteCommandType::Seek:
        // A seek claims nothing by itself, but it decides where the next unpositioned write lands,
        // so its offset has to be remembered rather than ignored.
        session.position = position.value_or(session.position);
        break;
    }

    if (session.size > writeSessionSizeCap || session.position > writeSessionSizeCap)
        return FileSystemStorageError::QuotaError;

    m_writeSessions.set(streamIdentifier, session);
    return std::nullopt;
}

// https://wicg.github.io/cross-origin-storage/#verify-and-store
std::optional<FileSystemStorageError> CrossOriginStorageRegistry::closeWritable(WebCore::FileSystemHandleIdentifier identifier, WebCore::FileSystemWritableFileStreamIdentifier streamIdentifier, WebCore::FileSystemWriteCloseReason reason)
{
    m_writeSessions.remove(streamIdentifier);

    auto contextIterator = m_handleContexts.find(identifier);
    if (contextIterator == m_handleContexts.end())
        return FileSystemStorageError::Unknown;
    auto& context = contextIterator->value;

    RefPtr handleRegistry = m_handleRegistry.get();
    RefPtr handle = handleRegistry ? handleRegistry->getHandle(identifier) : nullptr;
    if (!handle)
        return FileSystemStorageError::Unknown;

    // Give back this handle's contribution to the entry's outstanding-writer count, and reclaim
    // the entry if that was the last one and it was never successfully written. Both qualifiers
    // matter. The zero-count one protects a genuinely concurrent sibling write for the same hash
    // from having its entry deleted out from under it by the *other* writer's failure. The
    // never-written one is sharper: without it, any origin could delete an entry another origin
    // correctly stored, just by requesting a handle for its hash and deliberately writing garbage.
    auto releaseWriter = [&] {
        if (!context.countsAsPendingWriter)
            return;

        context.countsAsPendingWriter = false;
        auto entryIterator = m_entries.find(context.entryKey);
        if (entryIterator == m_entries.end())
            return;

        auto& entry = entryIterator->value;
        if (entry.pendingWriterCount)
            --entry.pendingWriterCount;

        if (entry.state == Entry::State::Pending && !entry.pendingWriterCount)
            removeEntry(context.entryKey);
    };

    // Every terminal outcome — a hash mismatch, an explicit abort, a read failure, a quota
    // rejection — funnels into this one cleanup path, rather than each inventing its own.
    auto failWrite = [&](std::optional<FileSystemStorageError> error) -> std::optional<FileSystemStorageError> {
        handle->closeWritable(streamIdentifier, WebCore::FileSystemWriteCloseReason::Aborted);
        releaseWriter();
        return error;
    };

    // An explicit abort() is a well-behaved abandonment signal, not a failure to report back: it
    // reclaims the entry immediately instead of waiting out the staleness timeout, and resolves.
    if (reason == WebCore::FileSystemWriteCloseReason::Aborted)
        return failWrite(std::nullopt);

    if (!context.isCreateHandle) {
        // A read handle was never authorized to write. Nothing reachable from script should get
        // here, but the registry must not depend on that.
        handle->closeWritable(streamIdentifier, WebCore::FileSystemWriteCloseReason::Aborted);
        return FileSystemStorageError::NoModificationAllowed;
    }

    auto entryIterator = m_entries.find(context.entryKey);
    if (entryIterator == m_entries.end())
        return failWrite(FileSystemStorageError::Unknown);

    // A COS hash can only ever be verified against the complete, final byte sequence: a later
    // seek() or truncate() can invalidate content already seen, so hashing happens once, here,
    // over the finished temporary file, never incrementally as write() calls arrive.
    auto writablePath = handle->activeWritablePath(streamIdentifier);
    if (writablePath.isEmpty())
        return failWrite(FileSystemStorageError::InvalidState);

    // Copied out rather than held by reference: making room for this write can evict other
    // entries, which would invalidate a reference into the registry's map.
    auto algorithm = entryIterator->value.algorithm;
    auto expectedValue = entryIterator->value.value;
    bool wasAlreadyWritten = entryIterator->value.state == Entry::State::Written;

    auto digestAlgorithm = PAL::Crypto::CryptoDigest::Algorithm::SHA_256;
    if (equalIgnoringASCIICase(algorithm, "SHA-1"_s))
        digestAlgorithm = PAL::Crypto::CryptoDigest::Algorithm::SHA_1;
    else if (equalIgnoringASCIICase(algorithm, "SHA-384"_s))
        digestAlgorithm = PAL::Crypto::CryptoDigest::Algorithm::SHA_384;
    else if (equalIgnoringASCIICase(algorithm, "SHA-512"_s))
        digestAlgorithm = PAL::Crypto::CryptoDigest::Algorithm::SHA_512;

    auto digest = PAL::Crypto::CryptoDigest::create(digestAlgorithm);
    if (!digest)
        return failWrite(FileSystemStorageError::Unknown);

    auto file = FileSystem::openFile(writablePath, FileSystem::FileOpenMode::Read);
    if (!file)
        return failWrite(FileSystemStorageError::Unknown);

    Vector<uint8_t> buffer(hashReadChunkSize);
    uint64_t writtenSize = 0;
    while (true) {
        auto bytesRead = file.read(buffer.mutableSpan());
        if (!bytesRead)
            return failWrite(FileSystemStorageError::Unknown);
        if (!*bytesRead)
            break;
        digest->addBytes(buffer.span().first(*bytesRead));
        writtenSize += *bytesRead;
    }
    file = { };

    // toHexString() emits uppercase, but a COS hash value is normatively lowercase, so comparing
    // the two directly fails for *every* write -- including correct ones. The specification makes
    // the value lowercase precisely so that this stays a plain string comparison rather than an
    // ASCII case-insensitive one, so lowercase the digest rather than loosening the comparison.
    if (digest->toHexString().convertToASCIILowercase() != expectedValue)
        return failWrite(FileSystemStorageError::DataMismatch);

    // Content-addressability means an origin rewriting bytes it already stored consumes no
    // additional quota: only a first successful write of a hash is charged.
    if (!wasAlreadyWritten && !makeRoomForWrite(context.requestingOrigin, writtenSize))
        return failWrite(FileSystemStorageError::QuotaError);

    // Eviction above may have rehashed the map, so look the entry up again rather than reusing an
    // iterator from before it ran.
    entryIterator = m_entries.find(context.entryKey);
    if (entryIterator == m_entries.end())
        return failWrite(FileSystemStorageError::Unknown);
    auto& entry = entryIterator->value;

    // Only now, with the bytes verified and the budget cleared, is the temporary file allowed to
    // be published into the entry's path.
    if (auto error = handle->closeWritable(streamIdentifier, WebCore::FileSystemWriteCloseReason::Completed))
        return failWrite(*error);
    FileSystem::deleteFile(writablePath);

    if (entry.state != Entry::State::Written) {
        entry.state = Entry::State::Written;
        entry.size = writtenSize;
        entry.attributedOrigin = context.requestingOrigin;
        chargeUsage(context.requestingOrigin, writtenSize);
    }

    if (!entry.storingOrigins.contains(context.requestingOrigin))
        entry.storingOrigins.append(context.requestingOrigin);

    if (context.countsAsPendingWriter) {
        context.countsAsPendingWriter = false;
        if (entry.pendingWriterCount)
            --entry.pendingWriterCount;
    }

    // A new site, not only the original storer, can widen an entry's scope, as long as it also
    // supplied bytes that hash to the entry's hash: any site that possesses the correct bytes is
    // by construction as authoritative as the original storer about what that hash denotes.
    upgradeResourceVisibility(entry, context.requestedScope, context.requestedOrigins);
    persistEntry(entry);

    return std::nullopt;
}

void CrossOriginStorageRegistry::handleClosed(WebCore::FileSystemHandleIdentifier identifier)
{
    auto context = m_handleContexts.take(identifier);
    if (!context.countsAsPendingWriter)
        return;

    // A create handle that was closed without ever being written through — the caller navigated
    // away, or simply never called createWritable() — gives its outstanding-writer contribution
    // back here, so a well-behaved abandonment does not have to wait out the staleness timeout.
    auto entryIterator = m_entries.find(context.entryKey);
    if (entryIterator == m_entries.end())
        return;

    auto& entry = entryIterator->value;
    if (entry.pendingWriterCount)
        --entry.pendingWriterCount;

    if (entry.state == Entry::State::Pending && !entry.pendingWriterCount)
        removeEntry(context.entryKey);
}

void CrossOriginStorageRegistry::connectionClosed(IPC::Connection::UniqueID connection)
{
    if (RefPtr manager = m_fileSystemStorageManager)
        manager->connectionClosed(connection);
}

uint64_t CrossOriginStorageRegistry::globalBudget() const
{
    auto capacity = m_volumeCapacityOverride;
    if (!capacity)
        capacity = FileSystem::volumeCapacity(m_path);
    if (!capacity)
        return 0;

    return CrossOriginStoragePolicy::globalBudgetForVolumeCapacity(*capacity);
}

uint64_t CrossOriginStorageRegistry::perOriginBudget() const
{
    return CrossOriginStoragePolicy::perOriginBudgetForGlobalBudget(globalBudget());
}

void CrossOriginStorageRegistry::chargeUsage(const String& origin, uint64_t size)
{
    m_totalBytes += size;
    auto addResult = m_bytesByOrigin.ensure(origin, [] {
        return static_cast<uint64_t>(0);
    });
    addResult.iterator->value += size;
}

void CrossOriginStorageRegistry::dischargeUsage(const String& origin, uint64_t size)
{
    m_totalBytes = m_totalBytes > size ? m_totalBytes - size : 0;

    auto iterator = m_bytesByOrigin.find(origin);
    if (iterator == m_bytesByOrigin.end())
        return;

    iterator->value = iterator->value > size ? iterator->value - size : 0;
    if (!iterator->value)
        m_bytesByOrigin.remove(iterator);
}

bool CrossOriginStorageRegistry::makeRoomForWrite(const String& writingOrigin, uint64_t size)
{
    // Only entries that are safe to evict at all are offered to the planner: a pending entry, or
    // one with a writer still outstanding, is somebody's in-flight write.
    Vector<CrossOriginStoragePolicy::EvictionCandidate> candidates;
    candidates.reserveInitialCapacity(m_entries.size());
    for (auto& keyValue : m_entries) {
        auto& entry = keyValue.value;
        if (entry.state != Entry::State::Written || entry.pendingWriterCount)
            continue;
        candidates.append({
            keyValue.key,
            entry.lastReadTime,
            entry.size,
            entry.attributedOrigin,
            entry.storingOrigins.size() == 1 ? entry.storingOrigins.first() : String { },
        });
    }

    auto plan = CrossOriginStoragePolicy::planEviction(WTF::move(candidates), writingOrigin, size, {
        m_totalBytes,
        m_bytesByOrigin.get(writingOrigin),
        globalBudget(),
        perOriginBudget(),
    });
    if (!plan.fits)
        return false;

    for (auto& key : plan.keysToEvict)
        removeEntry(key);

    // The nominal budget above can still allow a write that genuinely will not fit right now.
    // This is an internal-only safety net: the real free-space figure is never surfaced, so that
    // a rejection caused by a full disk is indistinguishable from an ordinary budget rejection.
    if (auto freeSpace = FileSystem::volumeFreeSpace(m_path)) {
        if (*freeSpace < size)
            return false;
    }

    return true;
}

bool CrossOriginStorageRegistry::persistEntry(const Entry& entry)
{
    // Only written entries are persisted. A pending entry's in-progress bytes live in a temporary
    // file that the writable stream machinery owns, and losing an in-flight write across a crash
    // is acceptable: there is no partial-write recovery logic to get wrong.
    if (entry.state != Entry::State::Written)
        return true;

    auto path = metadataPath(entry);
    if (!FileSystem::makeAllDirectories(FileSystem::parentPath(path)))
        return false;

    CrossOriginStoragePolicy::EntryRecord record;
    record.algorithm = entry.algorithm;
    record.value = entry.value;
    record.size = entry.size;
    record.lastReadTime = entry.lastReadTime;
    record.originsScope = entry.originsScope;
    record.attributedOrigin = entry.attributedOrigin;
    record.origins = entry.origins;
    record.storingOrigins = entry.storingOrigins;

    auto contents = record.serialize().utf8();

    // Write to a sibling temporary file and rename it into place, so that a reader can never
    // observe a half-written file. The temporary name is deliberately predictable from the final
    // one, so that startup can recognize and discard an orphan left by a crash.
    auto temporaryPath = makeString(path, temporaryFileExtension);
    {
        auto file = FileSystem::openFile(temporaryPath, FileSystem::FileOpenMode::Truncate);
        if (!file)
            return false;
        if (!file.write(byteCast<uint8_t>(contents.span()))) {
            file = { };
            FileSystem::deleteFile(temporaryPath);
            return false;
        }
    }

    if (!FileSystem::moveFile(temporaryPath, path)) {
        FileSystem::deleteFile(temporaryPath);
        return false;
    }

    return true;
}

void CrossOriginStorageRegistry::loadEntriesFromDisk()
{
    if (m_didLoadFromDisk)
        return;
    m_didLoadFromDisk = true;

    auto metadataRoot = FileSystem::pathByAppendingComponent(m_path, metadataDirectoryName);
    if (!FileSystem::fileExists(metadataRoot))
        return;

    for (auto& algorithmDirectory : FileSystem::listDirectory(metadataRoot)) {
        auto algorithmPath = FileSystem::pathByAppendingComponent(metadataRoot, algorithmDirectory);
        for (auto& fileName : FileSystem::listDirectory(algorithmPath)) {
            auto filePath = FileSystem::pathByAppendingComponent(algorithmPath, fileName);

            // A crash between writing a temporary metadata file and renaming it into place leaves
            // exactly this behind. It is always safe to discard: the rename never happened, so
            // nothing ever published it.
            if (fileName.endsWith(temporaryFileExtension)) {
                FileSystem::deleteFile(filePath);
                continue;
            }

            if (!fileName.endsWith(metadataFileExtension))
                continue;

            auto contents = FileSystem::readEntireFile(filePath);
            if (!contents) {
                FileSystem::deleteFile(filePath);
                continue;
            }

            auto record = CrossOriginStoragePolicy::EntryRecord::parse(String::fromUTF8(contents->span()));
            if (!record) {
                FileSystem::deleteFile(filePath);
                continue;
            }

            Entry entry;
            entry.algorithm = record->algorithm;
            entry.value = record->value;
            entry.state = Entry::State::Written;
            entry.size = record->size;
            entry.lastReadTime = record->lastReadTime;
            entry.createdTime = entry.lastReadTime;
            entry.originsScope = record->originsScope;
            entry.attributedOrigin = record->attributedOrigin;
            entry.origins = WTF::move(record->origins);
            entry.storingOrigins = WTF::move(record->storingOrigins);

            // A missing or truncated bytes file for otherwise-valid metadata degrades to absent
            // rather than to a handle that would hand out content not matching its own hash.
            auto entryBytesPath = bytesPath(entry);
            auto fileSize = FileSystem::fileSize(entryBytesPath);
            if (entry.algorithm.isEmpty() || entry.value.isEmpty() || !fileSize || *fileSize != entry.size) {
                FileSystem::deleteFile(filePath);
                FileSystem::deleteFile(entryBytesPath);
                continue;
            }

            chargeUsage(entry.attributedOrigin, entry.size);
            m_entries.add(entryKey(entry.algorithm, entry.value), WTF::move(entry));
        }
    }
}

void CrossOriginStorageRegistry::deleteAllData()
{
    m_entries.clear();
    m_handleContexts.clear();
    m_writeSessions.clear();
    m_bytesByOrigin.clear();
    m_totalBytes = 0;
    m_rateLimiter.clear();

    FileSystem::deleteNonEmptyDirectory(FileSystem::pathByAppendingComponent(m_path, bytesDirectoryName));
    FileSystem::deleteNonEmptyDirectory(FileSystem::pathByAppendingComponent(m_path, metadataDirectoryName));
}

// Revoke and collect, rather than delete-if-involved. The bytes of a shared entry persist for
// exactly as long as at least one origin still has a genuine storing relationship to them:
// surprising an uncleared site by deleting data it still depends on, purely as a side effect of an
// action it was never part of, is a worse failure mode than a cleared site's bytes surviving under
// a different, legitimate owner's relationship.
void CrossOriginStorageRegistry::revokeOriginsMatching(NOESCAPE const Function<bool(const String&)>& matches)
{
    Vector<String> keysToRemove;
    for (auto& keyValue : m_entries) {
        auto& entry = keyValue.value;
        bool changed = entry.storingOrigins.removeAllMatching(matches);
        changed |= entry.origins.removeAllMatching(matches);

        if (entry.storingOrigins.isEmpty()) {
            keysToRemove.append(keyValue.key);
            continue;
        }

        if (changed)
            persistEntry(entry);
    }

    for (auto& key : keysToRemove)
        removeEntry(key);
}

void CrossOriginStorageRegistry::deleteDataForOrigins(const HashSet<String>& serializedOrigins)
{
    revokeOriginsMatching([&](const String& origin) {
        return serializedOrigins.contains(origin);
    });
}

// Site-scoped matching goes through the same registrable-domain computation the rest of the
// storage layer already uses for this purpose, rather than a fresh comparison of its own: an
// entry stored by foo.example.com must be reachable by a clear request naming example.com.
void CrossOriginStorageRegistry::deleteDataForRegistrableDomains(const HashSet<WebCore::RegistrableDomain>& domains)
{
    revokeOriginsMatching([&](const String& serializedOrigin) {
        URL url { serializedOrigin };
        if (!url.isValid())
            return false;
        return domains.contains(WebCore::RegistrableDomain::uncheckedCreateFromHost(url.host().toString()));
    });
}

} // namespace WebKit
