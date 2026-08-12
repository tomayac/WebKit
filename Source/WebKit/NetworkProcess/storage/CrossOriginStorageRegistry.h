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

#include "Connection.h"
#include "CrossOriginStorageRateLimiter.h"
#include "FileSystemStorageError.h"
#include <WebCore/ClientOrigin.h>
#include <WebCore/CrossOriginStorageRequestData.h>
#include <WebCore/FileSystemHandleGlobalIdentifier.h>
#include <WebCore/FileSystemHandleIdentifier.h>
#include <WebCore/FileSystemWritableFileStreamIdentifier.h>
#include <WebCore/RegistrableDomain.h>
#include <wtf/Function.h>
#include <wtf/HashMap.h>
#include <wtf/HashSet.h>
#include <wtf/RefCountedAndCanMakeWeakPtr.h>
#include <wtf/TZoneMalloc.h>
#include <wtf/WallTime.h>

namespace WebCore {
enum class FileSystemWriteCloseReason : bool;
enum class FileSystemWriteCommandType : uint8_t;
}

namespace WebKit {

class FileSystemStorageHandleRegistry;
class FileSystemStorageManager;

// The Cross-Origin Storage registry: a single, content-addressable, *not* origin-partitioned map
// from COS hash to entry, shared by every origin that uses the feature.
// https://wicg.github.io/cross-origin-storage/
//
// It deliberately does not hang off the per-origin storage tree that backs the bucket file
// system, IndexedDB, and friends: those assume per-origin partitioning as a load-bearing
// property, which is exactly what content-addressable sharing is not. Instead it owns one
// FileSystemStorageManager of its own, rooted at a registry-wide directory, so that a handle it
// hands out is driven by the same file system machinery — and therefore the same IPC messages —
// as any other FileSystemFileHandle once it has been authorized.
//
// Every method here runs on NetworkStorageManager's work queue, which handles one message to
// completion before starting the next, so registry access is genuinely single-threaded and needs
// no locking of its own.
class CrossOriginStorageRegistry : public RefCountedAndCanMakeWeakPtr<CrossOriginStorageRegistry> {
    WTF_MAKE_TZONE_ALLOCATED(CrossOriginStorageRegistry);
public:
    static Ref<CrossOriginStorageRegistry> create(String&& path, FileSystemStorageHandleRegistry&, std::optional<uint64_t> volumeCapacityOverride);
    ~CrossOriginStorageRegistry();

    using HandleResult = Expected<std::pair<WebCore::FileSystemHandleGlobalIdentifier, WebCore::FileSystemHandleIdentifier>, FileSystemStorageError>;

    // https://wicg.github.io/cross-origin-storage/#requestfilehandle
    HandleResult requestFileHandle(IPC::Connection::UniqueID, const WebCore::ClientOrigin&, const WebCore::CrossOriginStorageRequestData&);

    bool ownsHandle(WebCore::FileSystemHandleIdentifier) const;

    // A handle can address an entry that is still "pending" — right after a create request,
    // before the corresponding write has completed. Reading one must fail, so that not even the
    // caller that requested it can observe an unverified placeholder as the file's contents.
    std::optional<FileSystemStorageError> prepareGetFile(WebCore::FileSystemHandleIdentifier);

    // Bounds what a single seek()/truncate() can claim before the authoritative budget check at
    // close() ever runs. Checked before the resize is attempted, not after.
    std::optional<FileSystemStorageError> checkWriteCommand(WebCore::FileSystemHandleIdentifier, WebCore::FileSystemWritableFileStreamIdentifier, WebCore::FileSystemWriteCommandType, std::optional<uint64_t> position, std::optional<uint64_t> size, size_t dataSize);

    // https://wicg.github.io/cross-origin-storage/#verify-and-store
    // Returns the error to reject the closing operation's promise with, or nullopt on success.
    // On success the caller has already published the written bytes.
    std::optional<FileSystemStorageError> closeWritable(WebCore::FileSystemHandleIdentifier, WebCore::FileSystemWritableFileStreamIdentifier, WebCore::FileSystemWriteCloseReason);

    void handleClosed(WebCore::FileSystemHandleIdentifier);
    void connectionClosed(IPC::Connection::UniqueID);

    // Website data removal.
    void deleteAllData();
    void deleteDataForOrigins(const HashSet<String>& serializedOrigins);
    void deleteDataForRegistrableDomains(const HashSet<WebCore::RegistrableDomain>&);
    uint64_t totalBytes() const { return m_totalBytes; }

    // Testing surface. The behaviours below are reachable from script only
    // indirectly and only nondeterministically -- eviction depends on a budget
    // derived from disk capacity, persistence needs a process restart to
    // observe, and GREASE'ing is deliberately unobservable by design -- so they
    // are driven here directly instead, which is also where their failure modes
    // are legible.
    WTF_EXPORT_DECLARATION void addWrittenEntryForTesting(const String& algorithm, const String& value, const String& storingOrigin, uint64_t size, WebCore::CrossOriginStorageOriginsScope, const Vector<String>& origins, WallTime lastReadTime);
    WTF_EXPORT_DECLARATION bool containsWrittenEntryForTesting(const String& algorithm, const String& value);
    WTF_EXPORT_DECLARATION size_t entryCountForTesting() const { return m_entries.size(); }
    WTF_EXPORT_DECLARATION uint64_t bytesForOriginForTesting(const String& origin) const { return m_bytesByOrigin.get(origin); }
    WTF_EXPORT_DECLARATION bool makeRoomForWriteForTesting(const String& writingOrigin, uint64_t size);
    WTF_EXPORT_DECLARATION uint64_t globalBudgetForTesting() const { return globalBudget(); }
    WTF_EXPORT_DECLARATION static bool shouldGreaseForTesting(uint64_t entrySize);

private:
    CrossOriginStorageRegistry(String&& path, FileSystemStorageHandleRegistry&, std::optional<uint64_t> volumeCapacityOverride);

    // https://wicg.github.io/cross-origin-storage/#cos-entries
    struct Entry {
        String algorithm;
        String value;
        enum class State : bool { Pending, Written };
        State state { State::Pending };
        // Outstanding writers: handles returned by a create request whose closing write has not
        // yet settled. Used only to decide whether a failed write is safe to clean up.
        unsigned pendingWriterCount { 0 };
        WebCore::CrossOriginStorageOriginsScope originsScope { WebCore::CrossOriginStorageOriginsScope::SameSite };
        // Ordered by recency, least-recently-used first. Only a genuine read refreshes an entry,
        // so a writer cannot keep a dormant origin alive by re-declaring it.
        Vector<String> origins;
        // Every origin that has independently completed a successful write of these bytes. An
        // origin here can always read the entry back, whatever its disclosure scope says.
        Vector<String> storingOrigins;
        uint64_t size { 0 };
        WallTime lastReadTime;
        WallTime createdTime;
        // The origin charged for this entry's bytes, which is whichever origin's write first
        // transitioned it to written.
        String attributedOrigin;
    };

    // What a handle handed out to script is for.
    struct HandleContext {
        String entryKey;
        String requestingOrigin;
        bool isCreateHandle { false };
        // The value verify-and-store will attempt to upgrade the entry's origins to, once this
        // handle is successfully written through.
        WebCore::CrossOriginStorageOriginsScope requestedScope { WebCore::CrossOriginStorageOriginsScope::SameSite };
        Vector<String> requestedOrigins;
        // Cleared once this handle's outstanding-writer count contribution has been given back,
        // so that a close() followed by handle destruction cannot decrement twice.
        bool countsAsPendingWriter { false };
    };

    HandleResult completeReadRequest(IPC::Connection::UniqueID, const String& requestingOrigin, const WebCore::CrossOriginStorageRequestData&);
    HandleResult completeCreateRequest(IPC::Connection::UniqueID, const String& requestingOrigin, const WebCore::CrossOriginStorageRequestData&);

    // https://wicg.github.io/cross-origin-storage/#determine-cos-disclosure
    bool determineDisclosure(const Entry&, const String& requestingOrigin);
    // https://wicg.github.io/cross-origin-storage/#apply-availability-gating
    bool applyAvailabilityGating(Entry&, const String& requestingOrigin);
    static bool shouldGrease(const Entry&);
    static bool shouldGrease(uint64_t entrySize);

    // https://wicg.github.io/cross-origin-storage/#upgrade-resource-visibility
    void upgradeResourceVisibility(Entry&, WebCore::CrossOriginStorageOriginsScope, const Vector<String>& requestedOrigins);

    static String entryKey(const String& algorithm, const String& value);
    String bytesPath(const Entry&) const;
    String metadataPath(const Entry&) const;

    Entry* findLiveEntry(const String& key);
    void removeEntry(const String& key);

    // Shared by every site-scoped clear: which origins a given action names is the only thing
    // that differs between them.
    void revokeOriginsMatching(NOESCAPE const Function<bool(const String& serializedOrigin)>&);

    bool persistEntry(const Entry&);
    void loadEntriesFromDisk();

    // Storage budget. Both figures derive from *total* disk capacity, never from currently
    // available free space: free space moves as unrelated things fill the disk, so a budget keyed
    // on it would leak real-time disk state to any page willing to trigger over-quota writes, and
    // would make the registry's own growth shrink its own future budget.
    uint64_t globalBudget() const;
    uint64_t perOriginBudget() const;
    bool makeRoomForWrite(const String& writingOrigin, uint64_t size);
    void chargeUsage(const String& origin, uint64_t size);
    void dischargeUsage(const String& origin, uint64_t size);

    String m_path;
    WeakPtr<FileSystemStorageHandleRegistry> m_handleRegistry;
    RefPtr<FileSystemStorageManager> m_fileSystemStorageManager;
    std::optional<uint64_t> m_volumeCapacityOverride;
    bool m_didLoadFromDisk { false };

    HashMap<String, Entry> m_entries;
    HashMap<WebCore::FileSystemHandleIdentifier, HandleContext> m_handleContexts;
    // Per-write-session tracked size and stream position, so that the streaming-time cap costs no
    // syscall per chunk. Position is tracked because an unpositioned write() continues from
    // wherever a preceding seek() left the stream, not from the end of the file.
    struct WriteSession {
        uint64_t size { 0 };
        uint64_t position { 0 };
    };
    HashMap<WebCore::FileSystemWritableFileStreamIdentifier, WriteSession> m_writeSessions;

    // Maintained incrementally at every mutation site rather than recomputed by scanning every
    // entry, which would be an O(n) walk on every single write.
    uint64_t m_totalBytes { 0 };
    HashMap<String, uint64_t> m_bytesByOrigin;

    CrossOriginStorageRateLimiter m_rateLimiter;
};

} // namespace WebKit
