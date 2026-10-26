package top.niunaijun.blackbox.core;

import android.util.Log;

import androidx.annotation.Keep;

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import dalvik.system.DexFile;
import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.app.BActivityThread;
import top.niunaijun.blackbox.entity.dump.DumpResult;
import top.niunaijun.blackbox.utils.DexUtils;
import top.niunaijun.blackbox.utils.FileUtils;
import top.niunaijun.blackbox.utils.compat.DexFileCompat;
import top.niunaijun.jnihook.MethodUtils;

import static top.niunaijun.blackbox.core.env.BEnvironment.EMPTY_JAR;

/**
 * Created by Milk on 4/9/21.
 * * ∧＿∧
 * (`･ω･∥
 * 丶　つ０
 * しーＪ
 * 此处无Bug
 */
public class VMCore {
    public static final String TAG = "VMCoreJava";

    static {
        new File("");
        System.loadLibrary("blackdex");
    }

    public static native void init(int apiLevel);

    public static native void enableIO();

    public static native void addIORule(String targetPath, String relocatePath);

    public static native void hideXposed();

    private static native void cookieDumpDex(long cookie, String dir, boolean fixMethod);

    private static native void hookDumpDex(String dir);

    public static void cookieDumpDex(ClassLoader classLoader, String packageName) {
        List<Long> cookies = DexFileCompat.getCookies(classLoader);
        File file = new File(BlackBoxCore.get().getDexDumpDir(), packageName);

        DumpResult result = new DumpResult();
        result.dir = file.getAbsolutePath();
        result.packageName = packageName;
        int availableProcessors = Runtime.getRuntime().availableProcessors();
        // Each worker may allocate a full in-memory DEX copy. Unbounded CPU-based
        // parallelism can exhaust memory when a target has many/large DEX files.
        int workerCount = Math.max(1, Math.min(4,
                Math.min(Math.max(1, availableProcessors), Math.max(1, cookies.size()))));
        ExecutorService executorService = Executors.newFixedThreadPool(workerCount);
        CountDownLatch countDownLatch = new CountDownLatch(cookies.size());
        AtomicInteger atomicInteger = new AtomicInteger(0);

        BlackBoxCore.getBDumpManager().noticeMonitor(result.dumpProcess(cookies.size(), atomicInteger.getAndIncrement()));
        try {
            for (int i = 0; i < cookies.size(); i++) {
                final long cookie = cookies.get(i);
                if (cookie == 0) {
                    countDownLatch.countDown();
                    BlackBoxCore.getBDumpManager().noticeMonitor(result.dumpProcess(cookies.size(), atomicInteger.getAndIncrement()));
                    continue;
                }
                FileUtils.mkdirs(file);
                if (!file.isDirectory()) {
                    throw new IllegalStateException("Unable to create DEX output directory: " + file.getAbsolutePath());
                }
                if (atomicInteger.get() == 1) {
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        throw interrupted;
                    }
                }
                executorService.execute(() -> {
                    try {
                        cookieDumpDex(cookie, file.getAbsolutePath(), BlackBoxCore.get().isFixCodeItem());
                    } catch (Throwable error) {
                        Log.e(TAG, "Cookie DEX dump failed for package " + packageName, error);
                    } finally {
                        try {
                            BlackBoxCore.getBDumpManager().noticeMonitor(
                                    result.dumpProcess(cookies.size(), atomicInteger.getAndIncrement()));
                        } catch (Throwable monitorError) {
                            Log.e(TAG, "Unable to report DEX dump progress for " + packageName, monitorError);
                        } finally {
                            countDownLatch.countDown();
                        }
                    }
                });
            }
            countDownLatch.await();
        } catch (InterruptedException interrupted) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
            Log.e(TAG, "Interrupted while waiting for DEX dump tasks for " + packageName, interrupted);
            return;
        } catch (RuntimeException error) {
            executorService.shutdownNow();
            Log.e(TAG, "Unable to schedule DEX dump tasks for " + packageName, error);
            throw error;
        } finally {
            executorService.shutdown();
        }

        File[] files = file.listFiles();
        if (files != null) {
            for (File dex : files) {
                if (dex.isFile() && dex.getName().endsWith(".dex")) {
                    DexUtils.fixDex(dex);
                }
            }
        }
    }

    @Keep
    public static int getCallingUid(int origCallingUid) {
//        if (origCallingUid > 0 && origCallingUid < Process.FIRST_APPLICATION_UID)
//            return origCallingUid;
//        // 非用户应用
//        if (origCallingUid > Process.LAST_APPLICATION_UID)
//            return origCallingUid;
//
//        Log.d(TAG, "origCallingUid: " + origCallingUid + " => " + BClient.getBaseVUid());
//        return BClient.getBaseVUid();
        return origCallingUid;
    }

    @Keep
    public static String redirectPath(String path) {
        return IOCore.get().redirectPath(path);
    }

    @Keep
    public static File redirectPath(File path) {
        return IOCore.get().redirectPath(path);
    }

    @Keep
    public static long[] loadEmptyDex() {
        try {
            DexFile dexFile = new DexFile(EMPTY_JAR);
            List<Long> cookies = DexFileCompat.getCookies(dexFile);
            long[] longs = new long[cookies.size()];
            for (int i = 0; i < cookies.size(); i++) {
                longs[i] = cookies.get(i);
            }
            return longs;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new long[]{};
    }

    @Keep
    public static Object findMethod(String className, String methodName, String signature) {
        try {
            className = className.replace("/", ".");
            if (className.startsWith("L")) {
                className = className.substring(1);
            }
            if (className.endsWith(";")) {
                className = className.substring(0, className.length() - 1);
            }
            ClassLoader classLoader = BActivityThread.getApplication().getClassLoader();
            Class<?> aClass = Class.forName(className, false, classLoader);
            if ("<init>".equals(methodName)) {
                Constructor<?>[] constructors = aClass.getDeclaredConstructors();
                for (Constructor<?> constructor : constructors) {
                    String desc = MethodUtils.getDesc(constructor);
                    if (signature.equals(desc)) {
                        return constructor;
                    }
                }
            }

            try {
                Method[] declaredMethods = aClass.getDeclaredMethods();
                for (Method declaredMethod : declaredMethods) {
                    if (declaredMethod.getName().equals(methodName)) {
                        String desc = MethodUtils.getDesc(declaredMethod);
                        if (desc.equals(signature)) {
                            return declaredMethod;
                        }
                    }
                }
            } catch (Throwable ignored) {
            }

            Method[] methods = aClass.getMethods();
            for (Method method : methods) {
                if (method.getName().equals(methodName)) {
                    String desc = MethodUtils.getDesc(method);
                    if (desc.equals(signature)) {
                        return method;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }
}
