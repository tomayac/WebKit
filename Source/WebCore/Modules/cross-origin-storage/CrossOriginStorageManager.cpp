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
#include "CrossOriginStorageManager.h"

#include "ClientOrigin.h"
#include "ContextDestructionObserverInlines.h"
#include "CrossOriginStorageLimits.h"
#include "Document.h"
#include "ExceptionOr.h"
#include "FileSystemFileHandle.h"
#include "FileSystemStorageConnection.h"
#include "JSDOMConvertInterface.h"
#include "JSDOMPromiseDeferred.h"
#include "JSFileSystemFileHandle.h"
#include "NavigatorBase.h"
#include "PermissionsPolicy.h"
#include "SecurityOrigin.h"
#include "StorageConnection.h"
#include "WorkerGlobalScope.h"
#include "WorkerStorageConnection.h"
#include <wtf/TZoneMallocInlines.h>
#include <wtf/URL.h>
#include <wtf/text/MakeString.h>

namespace WebCore {

WTF_MAKE_TZONE_ALLOCATED_IMPL(CrossOriginStorageManager);

Ref<CrossOriginStorageManager> CrossOriginStorageManager::create(NavigatorBase& navigator)
{
    return adoptRef(*new CrossOriginStorageManager(navigator));
}

CrossOriginStorageManager::CrossOriginStorageManager(NavigatorBase& navigator)
    : m_navigator(navigator)
{
}

CrossOriginStorageManager::~CrossOriginStorageManager() = default;

// https://wicg.github.io/cross-origin-storage/#validate-a-cos-request
// combined with https://wicg.github.io/cross-origin-storage/#normalize-requested-origins
ExceptionOr<CrossOriginStorageRequestData> CrossOriginStorageManager::validateAndNormalize(const RequestFileHandleHash& hash, const RequestFileHandleOptions& options)
{
    auto* algorithm = findCrossOriginStorageHashAlgorithm(hash.algorithm);
    if (!algorithm)
        return Exception { ExceptionCode::TypeError, makeString("'"_s, hash.algorithm, "' is not a hash algorithm recognized by the Web Cryptography API"_s) };

    if (!isValidCrossOriginStorageHashValue(hash.value, algorithm->hexDigestLength))
        return Exception { ExceptionCode::TypeError, makeString("Hash value must be "_s, algorithm->hexDigestLength, " lowercase hexadecimal characters for "_s, algorithm->name) };

    CrossOriginStorageRequestData request;
    request.algorithm = String { algorithm->name };
    request.value = hash.value;
    request.create = options.create;

    if (!options.origins)
        return request;

    Vector<String> candidates;
    WTF::switchOn(*options.origins, [&](const String& origins) {
        if (origins == "*"_s)
            request.originsScope = CrossOriginStorageOriginsScope::Wildcard;
        else
            candidates.append(origins);
    }, [&](const Vector<String>& origins) {
        candidates = origins;
    });

    if (request.originsScope == CrossOriginStorageOriginsScope::Wildcard)
        return request;

    if (candidates.size() > CrossOriginStorageLimits::maximumOriginsListLength)
        return Exception { ExceptionCode::TypeError, makeString("The origins list may contain at most "_s, CrossOriginStorageLimits::maximumOriginsListLength, " origins"_s) };

    request.originsScope = CrossOriginStorageOriginsScope::List;
    for (auto& candidate : candidates) {
        URL url { candidate };
        if (!url.isValid())
            return Exception { ExceptionCode::TypeError, makeString("'"_s, candidate, "' could not be parsed as a URL"_s) };

        Ref origin = SecurityOrigin::create(url);
        if (origin->isOpaque())
            return Exception { ExceptionCode::TypeError, makeString("'"_s, candidate, "' has an opaque origin"_s) };

        // Deduplicate, so that an entry's origins list stays duplicate-free from creation onward.
        auto serializedOrigin = origin->toString();
        if (!request.origins.contains(serializedOrigin))
            request.origins.append(WTF::move(serializedOrigin));
    }

    return request;
}

// Named distinctly rather than reusing StorageManager.cpp's identical-looking helper: both files
// are compiled into unified source bundles, so two file-scope types with the same name would be a
// redefinition rather than two independent locals.
struct CrossOriginStorageConnectionInfo {
    ThreadSafeWeakPtr<StorageConnection> connection;
    ClientOrigin origin;
};

static ExceptionOr<CrossOriginStorageConnectionInfo> crossOriginStorageConnectionInfo(NavigatorBase* navigator)
{
    if (!navigator)
        return Exception { ExceptionCode::InvalidStateError, "Navigator does not exist"_s };

    RefPtr context = navigator->scriptExecutionContext();
    if (!context)
        return Exception { ExceptionCode::InvalidStateError, "Context is invalid"_s };

    if (context->canAccessResource(ScriptExecutionContext::ResourceType::StorageManager) == ScriptExecutionContext::HasResourceAccess::No)
        return Exception { ExceptionCode::SecurityError, "Context cannot access storage"_s };

    RefPtr origin = context->securityOrigin();
    if (!origin)
        return Exception { ExceptionCode::InvalidStateError, "Context has no origin"_s };

    if (RefPtr document = dynamicDowncast<Document>(*context)) {
        if (RefPtr connection = document->storageConnection())
            return CrossOriginStorageConnectionInfo { *connection, { document->topOrigin().data(), origin->data() } };

        return Exception { ExceptionCode::InvalidStateError, "Connection is invalid"_s };
    }

    if (RefPtr globalScope = dynamicDowncast<WorkerGlobalScope>(*context))
        return CrossOriginStorageConnectionInfo { globalScope->storageConnection(), { globalScope->topOrigin().data(), origin->data() } };

    return Exception { ExceptionCode::NotSupportedError };
}

// https://wicg.github.io/cross-origin-storage/#requestfilehandle
void CrossOriginStorageManager::requestFileHandle(RequestFileHandleHash&& hash, RequestFileHandleOptions&& options, DOMPromiseDeferred<IDLInterface<FileSystemFileHandle>>&& promise)
{
    RefPtr navigator = m_navigator.get();
    RefPtr context = navigator ? navigator->scriptExecutionContext() : nullptr;

    // A document that is not allowed to use the "cross-origin-storage" policy-controlled feature
    // rejects every call, before any hash validation, registry lookup, or write occurs.
    if (RefPtr document = dynamicDowncast<Document>(context.get())) {
        if (!PermissionsPolicy::isFeatureEnabled(PermissionsPolicy::Feature::CrossOriginStorage, *document))
            return promise.reject(Exception { ExceptionCode::NotAllowedError, "Cross-Origin Storage is disabled by permissions policy"_s });
    }

    auto requestOrException = validateAndNormalize(hash, options);
    if (requestOrException.hasException())
        return promise.reject(requestOrException.releaseException());

    auto connectionInfoOrException = crossOriginStorageConnectionInfo(navigator.get());
    if (connectionInfoOrException.hasException())
        return promise.reject(connectionInfoOrException.releaseException());

    auto info = connectionInfoOrException.releaseReturnValue();
    RefPtr connection = info.connection.get();
    if (!connection)
        return promise.reject(Exception { ExceptionCode::InvalidStateError, "Connection is invalid"_s });

    connection->crossOriginStorageRequestFileHandle(WTF::move(info.origin), requestOrException.releaseReturnValue(), [promise = WTF::move(promise), weakNavigator = m_navigator](auto&& result) mutable {
        if (result.hasException())
            return promise.reject(result.releaseException());

        auto handleInfo = result.releaseReturnValue();
        RefPtr context = weakNavigator ? weakNavigator->scriptExecutionContext() : nullptr;
        if (!context) {
            handleInfo.connection->closeHandle(handleInfo.identifier);
            return promise.reject(Exception { ExceptionCode::InvalidStateError, "Context has stopped"_s });
        }

        Ref handle = FileSystemFileHandle::create(*context, String { emptyString() }, handleInfo.globalIdentifier, handleInfo.identifier, protect(*handleInfo.connection));
        promise.resolve(handle);
    });
}

} // namespace WebCore
