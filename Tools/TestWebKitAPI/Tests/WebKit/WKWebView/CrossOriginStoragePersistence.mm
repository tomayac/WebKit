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

#import "config.h"

#import "Helpers/PlatformUtilities.h"
#import "Helpers/Test.h"
#import "Helpers/cocoa/HTTPServer.h"
#import "Helpers/cocoa/TestWKWebView.h"
#import <WebKit/WKWebViewConfigurationPrivate.h>
#import <WebKit/WKWebsiteDataStorePrivate.h>
#import <WebKit/WebKit.h>
#import <WebKit/_WKWebsiteDataStoreConfiguration.h>
#import <wtf/FileSystem.h>
#import <wtf/RetainPtr.h>

// Cross-Origin Storage entries have to survive a restart -- a content-addressable cache that does
// not is pointless -- and that is the one property neither of the other test layers can reach. The
// web-platform-tests suite has no way to restart a browser, and the unit tests in
// CrossOriginStoragePolicy.cpp cover the on-disk record format without ever writing a file or
// starting a second process.
//
// The restart that matters is the *network process*: the registry lives there, so tearing down
// only the web process would leave it resident and the read below would be served from memory,
// passing while proving nothing.
//
// A failure here is silent by design. An entry that did not survive surfaces as an ordinary
// NotFoundError -- exactly what a hash that was never stored looks like -- so the write is asserted
// to have succeeded first, and the file is asserted to be on disk, before the reload is trusted to
// mean anything.

namespace TestWebKitAPI {

// Fixed rather than unique per run: the second half of the test addresses this same entry after the
// registry has been rebuilt from disk, so the content -- and therefore the hash that keys it -- has
// to be stable.
static constexpr auto testContent = "cross-origin-storage persistence probe"_s;
static constexpr auto testContentSHA256 = "01eaeaf6d50174e685f3d755768ed4d13e9965996a0d3754209a323f10c6fd5b"_s;

// These are async *function bodies*, not expressions: callAsyncJavaScript wraps the string in an
// async function, so the value has to leave via a top-level `return`. An IIFE here would evaluate
// correctly and still hand back undefined.
static NSString *storeScript()
{
    return @"const content = 'cross-origin-storage persistence probe';"
        "const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(content));"
        "const value = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');"
        "const handle = await navigator.crossOriginStorage.requestFileHandle("
        "  { algorithm: 'SHA-256', value }, { create: true });"
        "const writable = await handle.createWritable();"
        "await writable.write(new Blob([content]));"
        // close() is where verify-and-store runs, hashing the complete written byte sequence and
        // rejecting with DataError on a mismatch. Resolving here means stored *and* verified.
        "await writable.close();"
        "return value;";
}

static NSString *readScript()
{
    return @"const content = 'cross-origin-storage persistence probe';"
        "const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(content));"
        "const value = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');"
        "try {"
        // No create: true. A pure read, so it can only succeed if the registry reloaded from disk.
        "  const handle = await navigator.crossOriginStorage.requestFileHandle({ algorithm: 'SHA-256', value });"
        "  return await (await handle.getFile()).text();"
        "} catch (error) {"
        "  return 'error:' + error.name;"
        "}";
}

static RetainPtr<NSURL> makeStorageDirectory()
{
    RetainPtr directory = [NSURL fileURLWithPath:[NSTemporaryDirectory() stringByAppendingPathComponent:@"CrossOriginStoragePersistence"] isDirectory:YES];
    // A leftover directory from an earlier run would make the write step redundant and could let
    // the read step pass on stale data rather than on what this run stored.
    [[NSFileManager defaultManager] removeItemAtURL:directory.get() error:nil];
    [[NSFileManager defaultManager] createDirectoryAtURL:directory.get() withIntermediateDirectories:YES attributes:nil error:nil];
    return directory;
}

static RetainPtr<WKWebViewConfiguration> makeConfiguration(NSURL *storageDirectory)
{
    RetainPtr storeConfiguration = adoptNS([[_WKWebsiteDataStoreConfiguration alloc] init]);
    [storeConfiguration setGeneralStorageDirectory:storageDirectory];
    RetainPtr store = adoptNS([[WKWebsiteDataStore alloc] _initWithConfiguration:storeConfiguration.get()]);

    RetainPtr configuration = adoptNS([WKWebViewConfiguration new]);
    [configuration setWebsiteDataStore:store.get()];
    return configuration;
}

TEST(CrossOriginStorage, EntriesSurviveANetworkProcessRestart)
{
    // 127.0.0.1 is a potentially trustworthy origin, so this is a secure context and the feature is
    // exposed without any TLS setup.
    HTTPServer server({ { "/"_s, { "<!DOCTYPE html><body>cross-origin storage persistence"_s } } });

    RetainPtr storageDirectory = makeStorageDirectory();
    RetainPtr configuration = makeConfiguration(storageDirectory.get());

    @autoreleasepool {
        RetainPtr webView = adoptNS([[TestWKWebView alloc] initWithFrame:CGRectMake(0, 0, 800, 600) configuration:configuration.get()]);
        [webView synchronouslyLoadRequest:server.request()];

        EXPECT_TRUE([[webView objectByEvaluatingJavaScript:@"!!navigator.crossOriginStorage"] boolValue]);

        RetainPtr storedHash = (NSString *)[webView objectByCallingAsyncFunction:storeScript() withArguments:@{ }];
        EXPECT_WK_STREQ(testContentSHA256.createNSString().get(), storedHash.get());

        // Read it back before the restart, so that a failure after the restart can be attributed to
        // the reload path rather than to the write.
        RetainPtr beforeRestart = (NSString *)[webView objectByCallingAsyncFunction:readScript() withArguments:@{ }];
        EXPECT_WK_STREQ(testContent.createNSString().get(), beforeRestart.get());
    }

    // The bytes and the metadata record are separate files, and a metadata record whose bytes file
    // is missing is discarded at load time, so both have to be there for the reload to mean
    // anything. Asserting it here distinguishes "never written" from "written but not reloaded".
    RetainPtr registryDirectory = [storageDirectory URLByAppendingPathComponent:@"CrossOriginStorage"];
    RetainPtr bytesPath = [[[registryDirectory URLByAppendingPathComponent:@"files"] URLByAppendingPathComponent:@"SHA-256"] URLByAppendingPathComponent:testContentSHA256.createNSString().get()];
    RetainPtr metadataPath = [[[registryDirectory URLByAppendingPathComponent:@"metadata"] URLByAppendingPathComponent:@"SHA-256"] URLByAppendingPathComponent:[testContentSHA256.createNSString().get() stringByAppendingString:@".meta"]];
    EXPECT_TRUE([[NSFileManager defaultManager] fileExistsAtPath:[bytesPath path]]);
    EXPECT_TRUE([[NSFileManager defaultManager] fileExistsAtPath:[metadataPath path]]);

    // The restart itself. Everything the registry knows is now only on disk.
    [[configuration websiteDataStore] _terminateNetworkProcess];

    RetainPtr configurationAfterRestart = makeConfiguration(storageDirectory.get());
    RetainPtr webViewAfterRestart = adoptNS([[TestWKWebView alloc] initWithFrame:CGRectMake(0, 0, 800, 600) configuration:configurationAfterRestart.get()]);
    [webViewAfterRestart synchronouslyLoadRequest:server.request()];

    RetainPtr afterRestart = (NSString *)[webViewAfterRestart objectByCallingAsyncFunction:readScript() withArguments:@{ }];
    EXPECT_WK_STREQ(testContent.createNSString().get(), afterRestart.get());

    [[NSFileManager defaultManager] removeItemAtURL:storageDirectory.get() error:nil];
}

TEST(CrossOriginStorage, AnEntryThatWasNeverStoredIsNotFoundAfterARestart)
{
    // The control for the test above. Without it, a read path that resolved for anything at all --
    // or an assertion that never actually ran -- would be indistinguishable from working
    // persistence, since both tests would report success.
    HTTPServer server({ { "/"_s, { "<!DOCTYPE html><body>cross-origin storage persistence"_s } } });

    RetainPtr storageDirectory = makeStorageDirectory();
    RetainPtr configuration = makeConfiguration(storageDirectory.get());

    @autoreleasepool {
        RetainPtr webView = adoptNS([[TestWKWebView alloc] initWithFrame:CGRectMake(0, 0, 800, 600) configuration:configuration.get()]);
        [webView synchronouslyLoadRequest:server.request()];
        EXPECT_TRUE([[webView objectByEvaluatingJavaScript:@"!!navigator.crossOriginStorage"] boolValue]);
    }

    [[configuration websiteDataStore] _terminateNetworkProcess];

    RetainPtr configurationAfterRestart = makeConfiguration(storageDirectory.get());
    RetainPtr webViewAfterRestart = adoptNS([[TestWKWebView alloc] initWithFrame:CGRectMake(0, 0, 800, 600) configuration:configurationAfterRestart.get()]);
    [webViewAfterRestart synchronouslyLoadRequest:server.request()];

    RetainPtr afterRestart = (NSString *)[webViewAfterRestart objectByCallingAsyncFunction:readScript() withArguments:@{ }];
    EXPECT_WK_STREQ(@"error:NotFoundError", afterRestart.get());

    [[NSFileManager defaultManager] removeItemAtURL:storageDirectory.get() error:nil];
}

} // namespace TestWebKitAPI
