//
// Created by Milk on 4/10/21.
//

#include "IO.h"
#include "utils/Log.h"
#include <string>
#include <new>
#include <cstring>
#include <cstdlib>

jmethodID getAbsolutePathMethodId;

list<IO::RelocateInfo> relocate_rule;

char *replace(const char *str, const char *src, const char *dst) {
    if (str == nullptr || src == nullptr || dst == nullptr || src[0] == '\0') {
        return nullptr;
    }

    // Build the result with std::string rather than calculating the size with
    // unsigned strlen subtraction (which underflows when dst is shorter) and
    // reading uninitialized memory via strlen(result).
    std::string result(str);
    const std::string needle(src);
    const std::string replacement(dst);
    size_t pos = 0;
    while ((pos = result.find(needle, pos)) != std::string::npos) {
        result.replace(pos, needle.size(), replacement);
        pos += replacement.size();
    }

    char *output = static_cast<char *>(malloc(result.size() + 1));
    if (output == nullptr) {
        return nullptr;
    }
    memcpy(output, result.c_str(), result.size() + 1);
    return output;
}

const char *IO::redirectPath(const char *__path) {
    list<IO::RelocateInfo>::iterator iterator;
    for (iterator = relocate_rule.begin(); iterator != relocate_rule.end(); ++iterator) {
        IO::RelocateInfo info = *iterator;
        if (__path != nullptr && info.targetPath != nullptr &&
            info.targetPath[0] != '\0' && info.relocatePath != nullptr &&
            strstr(__path, info.targetPath) && !strstr(__path, "/virtual/")) {
            char *ret = replace(__path, info.targetPath, info.relocatePath);
            // The returned path is consumed by the native hook and intentionally
            // remains valid after this function returns.
            if (ret != nullptr) {
                return ret;
            }
            ALOGE("Unable to allocate redirected path for '%s'", __path);
        }
    }
    return __path;
}

jstring IO::redirectPath(JNIEnv *env, jstring path) {
//    const char * pathC = env->GetStringUTFChars(path, JNI_FALSE);
//    const char *redirect = redirectPath(pathC);
//    env->ReleaseStringUTFChars(path, pathC);
//    return env->NewStringUTF(redirect);
    return VmCore::redirectPathString(env, path);
}

jobject IO::redirectPath(JNIEnv *env, jobject path) {
//    auto pathStr =
//            reinterpret_cast<jstring>(env->CallObjectMethod(path, getAbsolutePathMethodId));
//    jstring redirect = redirectPath(env, pathStr);
//    jobject file = env->NewObject(fileClazz, fileNew, redirect);
//    env->DeleteLocalRef(pathStr);
//    env->DeleteLocalRef(redirect);
    return VmCore::redirectPathFile(env, path);
}

void IO::addRule(const char *targetPath, const char *relocatePath) {
    IO::RelocateInfo info{};
    info.targetPath = targetPath;
    info.relocatePath = relocatePath;
    relocate_rule.push_back(info);
}

void IO::init(JNIEnv *env) {
    jclass tmpFile = env->FindClass("java/io/File");
    getAbsolutePathMethodId = env->GetMethodID(tmpFile, "getAbsolutePath", "()Ljava/lang/String;");
}
