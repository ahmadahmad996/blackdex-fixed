package top.niunaijun.blackbox.utils;

import java.io.File;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import top.niunaijun.blackbox.BlackBoxCore;

/**
 * Created by Milk on 3/2/21.
 * * ∧＿∧
 * (`･ω･∥
 * 丶　つ０
 * しーＪ
 * 此处无Bug
 */
public class AbiUtils {
    private final Set<String> mLibs = new HashSet<>();
    private static final Map<File, AbiUtils> sAbiUtilsMap = new HashMap<>();

    public static boolean isSupport(File apkFile) {
        AbiUtils abiUtils = sAbiUtilsMap.get(apkFile);
        if (abiUtils == null) {
            abiUtils = new AbiUtils(apkFile);
            sAbiUtilsMap.put(apkFile, abiUtils);
        }
        if (abiUtils.isEmptyAib()) {
            return true;
        }

        if (BlackBoxCore.is64Bit()) {
            return abiUtils.is64Bit();
        } else {
            return abiUtils.is32Bit();
        }
    }

    public AbiUtils(File apkFile) {
        ZipFile zipFile = null;
        try {
            zipFile = new ZipFile(apkFile);
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry zipEntry = entries.nextElement();
                String name = zipEntry.getName();
                if (name.startsWith("lib/arm64-v8a/")) {
                    mLibs.add("arm64-v8a");
                } else if (name.startsWith("lib/armeabi-v7a/")) {
                    mLibs.add("armeabi-v7a");
                } else if (name.startsWith("lib/armeabi/")) {
                    mLibs.add("armeabi");
                } else if (name.startsWith("lib/x86_64/")) {
                    mLibs.add("x86_64");
                } else if (name.startsWith("lib/x86/")) {
                    mLibs.add("x86");
                } else if (name.startsWith("lib/")) {
                    // Remember other native ABIs too, so an APK containing only
                    // an unsupported ABI is not mistaken for a Java-only APK.
                    int abiEnd = name.indexOf('/', 4);
                    if (abiEnd > 4) {
                        mLibs.add(name.substring(4, abiEnd));
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            CloseUtils.close(zipFile);
        }
    }

    public boolean is64Bit() {
        // This checkout packages ARM64 native code in BlackDex64; x86_64 is
        // not interchangeable with arm64-v8a merely because both are 64-bit.
        return mLibs.contains("arm64-v8a");
    }

    public boolean is32Bit() {
        // This checkout packages ARM32 native code in BlackDex32; x86 is not
        // interchangeable with ARM even when the process bitness matches.
        return mLibs.contains("armeabi") || mLibs.contains("armeabi-v7a");
    }

    public boolean isEmptyAib() {
        return mLibs.isEmpty();
    }
}
