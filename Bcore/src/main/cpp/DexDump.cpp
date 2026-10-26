//
// Created by Milk on 2021/5/16.
//

#include "DexDump.h"
#include "utils/HexDump.h"
#include "utils/Log.h"
#include "VmCore.h"
#include "utils/PointerCheck.h"
#include "jnihook/Art.h"
#include "jnihook/ArtM.h"

#include <cstdio>
#include <fcntl.h>
#include <cstring>
#include <cstdlib>
#include <map>
#include <list>
#include <set>
#include <string>
#include <cerrno>
#include <cstdint>
#include <mutex>
#include <sys/mman.h>
#include "unistd.h"

#include "dex/dex_file-inl.h"
#include "dex/dex_file_loader.h"
#include "jnihook/JniHook.h"
#include "xhook/xhook.h"
#include "Dobby/include/dobby.h"

#define _uintval(p)               reinterpret_cast<uintptr_t>(p)
#define _ptr(p)                   reinterpret_cast<void *>(p)
#define _align_up(x, n)           (((x) + ((n) - 1)) & ~((n) - 1))
#define _align_down(x, n)         ((x) & -(n))
#define _page_size                4096
#define _page_align(n)            _align_up(static_cast<uintptr_t>(n), _page_size)
#define _ptr_align(x)             _ptr(_align_down(reinterpret_cast<uintptr_t>(x), _page_size))
#define _make_rwx(p, n)           ::mprotect(_ptr_align(p), \
                                              _page_align(_uintval(p) + n) != _page_align(_uintval(p)) ? _page_align(n) + _page_size : _page_align(n), \
                                              PROT_READ | PROT_WRITE | PROT_EXEC)

using namespace std;
static int beginOffset = -2;
static std::mutex beginOffsetMutex;
static std::string dumpPath;
static std::set<const void *> dumped;
static std::mutex dumpedMutex;

static bool writeFully(int fd, const void *data, size_t size) {
    const char *cursor = static_cast<const char *>(data);
    size_t remaining = size;
    while (remaining > 0) {
        ssize_t written = write(fd, cursor, remaining);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return false;
        }
        cursor += written;
        remaining -= static_cast<size_t>(written);
    }
    return fsync(fd) == 0;
}

static bool writeDexFile(const char *path, const void *data, size_t size) {
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) {
        ALOGE("Unable to open DEX output '%s': errno=%d (%s)",
              path, errno, strerror(errno));
        return false;
    }
    bool success = writeFully(fd, data, size);
    int savedErrno = errno;
    if (!success && savedErrno == 0) {
        savedErrno = EIO;
    }
    if (close(fd) != 0 && success) {
        success = false;
        savedErrno = errno;
    }
    if (!success) {
        remove(path);
        ALOGE("Unable to write complete DEX output '%s': errno=%d (%s)",
              path, savedErrno, strerror(savedErrno));
    }
    return success;
}

void handleDumpByDexFile(void *dex_file) {
    const char magic[8] = {0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00};
    if (!PointerCheck::check(dex_file)) {
        ALOGW("Skipping DEX dump: invalid DexFile pointer");
        return;
    }

    // Deduplicate by DexFile identity, not size: distinct multidex entries can
    // legitimately have the same byte length. LoadMethod can be called concurrently.
    std::lock_guard<std::mutex> lock(dumpedMutex);
    if (dumped.find(dex_file) != dumped.end()) {
        return;
    }
    auto dexFile = static_cast<art_lkchan::DexFile *>(dex_file);
    const size_t size = dexFile->Size();
    if (size < 0x70) {
        ALOGW("Skipping DEX dump: invalid DEX size %zu", size);
        return;
    }

    void *buffer = malloc(size);
    if (!buffer) {
        ALOGE("Unable to allocate %zu bytes for DEX dump", size);
        return;
    }
    memcpy(buffer, dexFile->Begin(), size);
    memcpy(buffer, magic, sizeof(magic));

    const bool kVerifyChecksum = false;
    const bool kVerify = true;
    const art_lkchan::DexFileLoader dex_file_loader;
    std::string error_msg;
    std::vector<std::unique_ptr<const art_lkchan::DexFile>> dex_files;
    if (!dex_file_loader.OpenAll(reinterpret_cast<const uint8_t *>(buffer),
                                 size, "", kVerify, kVerifyChecksum,
                                 &error_msg, &dex_files)) {
        ALOGE("Invalid DEX data; refusing to write output: %s", error_msg.c_str());
        free(buffer);
        return;
    }

    char path[1024];
    int pathLength = snprintf(path, sizeof(path), "%s/hook_%zu_%p.dex",
                              dumpPath.c_str(), size, dex_file);
    if (pathLength < 0 || static_cast<size_t>(pathLength) >= sizeof(path)) {
        ALOGE("DEX output path is too long");
        free(buffer);
        return;
    }

    if (writeDexFile(path, buffer, size)) {
        ALOGI("Hook DEX dump saved: %s (%zu bytes)", path, size);
        dumped.insert(dex_file);
    }
    free(buffer);
}

HOOK_JNI(int, kill, pid_t __pid, int __signal) {
    ALOGE("hooked so kill");
    return 0;
}

HOOK_JNI(int, killpg, int __pgrp, int __signal) {
    ALOGE("hooked so killpg");
    return 0;
}

HOOK_FUN(void, LoadMethodO, void *thiz,
         void *dex_file,
         void *method,
         void *klass,
         void *dst) {
    orig_LoadMethodO(thiz, dex_file, method, klass, dst);
    handleDumpByDexFile(dex_file);
}

HOOK_FUN(void, LoadMethodM, void *thiz,
         void *thread,
         void *dex_file,
         void *method,
         void *klass,
         void *dst) {
    orig_LoadMethodM(thiz, thread, dex_file, method, klass, dst);
    handleDumpByDexFile(dex_file);
}

HOOK_FUN(void, LoadMethodL, void *thiz,
         void *thread,
         void *dex_file,
         void *method,
         void *klass) {
    orig_LoadMethodL(thiz, thread, dex_file, method, klass);
    handleDumpByDexFile(dex_file);
}

void init(JNIEnv *env) {
    const char *soName = ".*\\.so$";
    xhook_register(soName, "kill", (void *) new_kill,
                   (void **) (&orig_kill));
    xhook_register(soName, "killpg", (void *) new_killpg,
                   (void **) (&orig_killpg));
    xhook_refresh(0);

    jlongArray emptyCookie = VmCore::loadEmptyDex(env);
    jsize arrSize = env->GetArrayLength(emptyCookie);
    if (env->ExceptionCheck() == JNI_TRUE) {
        return;
    }
    jlong *long_data = env->GetLongArrayElements(emptyCookie, nullptr);

    for (int i = 0; i < arrSize; ++i) {
        jlong cookie = long_data[i];
        if (cookie == 0) {
            continue;
        }
        auto dex = reinterpret_cast<char *>(cookie);
        for (int ii = 0; ii < 10; ++ii) {
            auto value = *(size_t *) (dex + ii * sizeof(size_t));
            if (value == 1872) {
                beginOffset = ii - 1;
                // auto dexBegin = *(size_t *) (dex + beginOffset * sizeof(size_t));
                // HexDump(reinterpret_cast<char *>(dexBegin), 10, 0);
                env->ReleaseLongArrayElements(emptyCookie, long_data, 0);
                return;
            }
        }
    }
    env->ReleaseLongArrayElements(emptyCookie, long_data, 0);
    beginOffset = -1;
}

void fixCodeItem(JNIEnv *env, const art_lkchan::DexFile *dex_file_, size_t begin) {
    for (size_t classdef_ctr = 0; classdef_ctr < dex_file_->NumClassDefs(); ++classdef_ctr) {
        const art_lkchan::DexFile::ClassDef &cd = dex_file_->GetClassDef(classdef_ctr);
        const uint8_t *class_data = dex_file_->GetClassData(cd);
        auto &classTypeId = dex_file_->GetTypeId(cd.class_idx_);
        std::string class_name = dex_file_->GetTypeDescriptor(classTypeId);

        if (class_data != nullptr) {
            art_lkchan::ClassDataItemIterator cdit(*dex_file_, class_data);
            cdit.SkipAllFields();
            while (cdit.HasNextMethod()) {
                const art_lkchan::DexFile::MethodId &method_id_item = dex_file_->GetMethodId(
                        cdit.GetMemberIndex());
                auto method_name = dex_file_->GetMethodName(method_id_item);
                auto method_signature = dex_file_->GetMethodSignature(
                        method_id_item).ToString().c_str();
                auto java_method = VmCore::findMethod(env, class_name.c_str(), method_name,
                                                      method_signature);
                if (java_method) {
                    auto artMethod = ArtM::GetArtMethod(env, java_method);
                    const art_lkchan::DexFile::CodeItem *orig_code_item = cdit.GetMethodCodeItem();
                    if (cdit.GetMethodCodeItemOffset() && orig_code_item) {
                        auto codeItemSize = dex_file_->GetCodeItemSize(*orig_code_item);
                        auto new_code_item =
                                begin + ArtM::GetArtMethodDexCodeItemOffset(artMethod);
                        memcpy((void *) orig_code_item,
                               (void *) new_code_item,
                               codeItemSize);
                    }
                } else {
                    env->ExceptionClear();
                }
                cdit.Next();
            }
        }
    }
}

void DexDump::cookieDumpDex(JNIEnv *env, jlong cookie, jstring dir, jboolean fix) {
    if (cookie == 0 || dir == nullptr) {
        ALOGE("Cookie DEX dump rejected: null cookie or output directory");
        return;
    }
    {
        std::lock_guard<std::mutex> initLock(beginOffsetMutex);
        if (beginOffset == -2) {
            init(env);
        }
    }
    if (beginOffset == -1) {
        ALOGE("Cookie DEX dump unsupported: could not determine DexFile cookie layout");
        return;
    }

    const char magic[8] = {0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00};
    auto base = reinterpret_cast<char *>(static_cast<uintptr_t>(cookie));
    if (!PointerCheck::check(base)) {
        ALOGE("Cookie DEX dump rejected: invalid cookie pointer");
        return;
    }
    auto begin = *(size_t *) (base + beginOffset * sizeof(size_t));
    if (!PointerCheck::check(reinterpret_cast<void *>(begin))) {
        ALOGE("Cookie DEX dump rejected: invalid DEX begin pointer");
        return;
    }

    const char *dirC = env->GetStringUTFChars(dir, nullptr);
    if (dirC == nullptr) {
        ALOGE("Cookie DEX dump failed: unable to read output directory string");
        return; // JVM has raised an exception; do not perform more JNI calls.
    }

    bool completed = false;
    const size_t size = *reinterpret_cast<const uint32_t *>(begin + 0x20);
    if (size < 0x70) {
        ALOGE("Cookie DEX dump rejected: invalid DEX size %zu", size);
    } else {
        void *buffer = malloc(size);
        if (!buffer) {
            ALOGE("Unable to allocate %zu bytes for cookie DEX dump", size);
        } else {
            memcpy(buffer, reinterpret_cast<const void *>(begin), size);
            memcpy(buffer, magic, sizeof(magic));

            const bool kVerifyChecksum = false;
            const bool kVerify = true;
            const art_lkchan::DexFileLoader dex_file_loader;
            std::string error_msg;
            std::vector<std::unique_ptr<const art_lkchan::DexFile>> dex_files;
            if (!dex_file_loader.OpenAll(reinterpret_cast<const uint8_t *>(buffer),
                                         size, "", kVerify, kVerifyChecksum,
                                         &error_msg, &dex_files)) {
                ALOGE("Invalid cookie DEX data; refusing to write output: %s",
                      error_msg.c_str());
            } else {
                if (fix) {
                    fixCodeItem(env, dex_files[0].get(), begin);
                }
                char path[1024];
                int pathLength = snprintf(path, sizeof(path), "%s/cookie_%zu_%p.dex",
                                          dirC, size, reinterpret_cast<void *>(begin));
                if (pathLength < 0 || static_cast<size_t>(pathLength) >= sizeof(path)) {
                    ALOGE("Cookie DEX output path is too long");
                } else {
                    completed = writeDexFile(path, buffer, size);
                    if (completed) {
                        ALOGI("Cookie DEX dump saved: %s (%zu bytes)", path, size);
                    }
                }
            }
            free(buffer);
        }
    }
    env->ReleaseStringUTFChars(dir, dirC);
}

void DexDump::hookDumpDex(JNIEnv *env, jstring dir) {
    if (dir == nullptr) {
        ALOGE("Hook DEX dump rejected: null output directory");
        return;
    }
    const char *dirC = env->GetStringUTFChars(dir, nullptr);
    if (dirC == nullptr) {
        ALOGE("Hook DEX dump failed: unable to read output directory string");
        return;
    }
    dumpPath.assign(dirC);
    env->ReleaseStringUTFChars(dir, dirC);
    const char *libart = "libart.so";

    // L
    void *loadMethod = DobbySymbolResolver(libart,
                                           "_ZN3art11ClassLinker10LoadMethodEPNS_6ThreadERKNS_7DexFileERKNS_21ClassDataItemIteratorENS_6HandleINS_6mirror5ClassEEE");
    if (!loadMethod) {
        // M
        loadMethod = DobbySymbolResolver(libart,
                                         "_ZN3art11ClassLinker10LoadMethodEPNS_6ThreadERKNS_7DexFileERKNS_21ClassDataItemIteratorENS_6HandleINS_6mirror5ClassEEEPNS_9ArtMethodE");
    }
    if (!loadMethod) {
        // O
        loadMethod = DobbySymbolResolver(libart,
                                         "_ZN3art11ClassLinker10LoadMethodERKNS_7DexFileERKNS_13ClassAccessor6MethodENS_6HandleINS_6mirror5ClassEEEPNS_9ArtMethodE");
    }

    if (!loadMethod) {
        ALOGE("Hook DEX dump unsupported: no compatible ClassLinker::LoadMethod symbol found for API %d",
              android_get_device_api_level());
        return;
    }
    if (_make_rwx(loadMethod, _page_size) != 0) {
        ALOGE("Unable to change protection on ClassLinker::LoadMethod");
        return;
    }
    if (loadMethod) {
        int hookStatus;
        if (android_get_device_api_level() >= __ANDROID_API_O__) {
            hookStatus = DobbyHook(loadMethod, (void *) new_LoadMethodO,
                                   (void **) &orig_LoadMethodO);
        } else if (android_get_device_api_level() >= __ANDROID_API_M__) {
            hookStatus = DobbyHook(loadMethod, (void *) new_LoadMethodM,
                                   (void **) &orig_LoadMethodM);
        } else {
            hookStatus = DobbyHook(loadMethod, (void *) new_LoadMethodL,
                                   (void **) &orig_LoadMethodL);
        }
        if (hookStatus != 0) {
            ALOGE("Failed to install ClassLinker::LoadMethod hook: status=%d", hookStatus);
        }
    }
}

