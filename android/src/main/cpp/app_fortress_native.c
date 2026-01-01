/**
 * Native Security Layer for App Fortress
 * 
 * This C code provides additional security checks that are harder to
 * reverse engineer than Kotlin/Java code.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <android/log.h>

#define LOG_TAG "AppFortressNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ============================================================================
// ROOT DETECTION
// ============================================================================

static const char *su_paths[] = {
    "/system/bin/su", "/system/xbin/su", "/sbin/su",
    "/system/su", "/system/bin/.ext/.su",
    "/data/local/xbin/su", "/data/local/bin/su",
    "/data/local/su", "/su/bin/su", "/magisk/.core/bin/su",
    NULL
};

static const char *root_indicators[] = {
    "/system/app/Superuser.apk", "/sbin/.magisk",
    "/cache/.disable_magisk", "/dev/.magisk.unblock",
    "/data/adb/magisk", "/data/adb/magisk.img",
    NULL
};

static int check_su_binary() {
    for (int i = 0; su_paths[i] != NULL; i++) {
        if (access(su_paths[i], F_OK) == 0) {
            return 1;
        }
    }
    return 0;
}

static int check_root_files() {
    for (int i = 0; root_indicators[i] != NULL; i++) {
        if (access(root_indicators[i], F_OK) == 0) {
            return 1;
        }
    }
    return 0;
}

JNIEXPORT jboolean JNICALL
Java_com_app_fortress_AppFortressPlugin_nativeIsRooted(JNIEnv *env, jobject thiz) {
    return check_su_binary() || check_root_files();
}

// ============================================================================
// EMULATOR DETECTION
// ============================================================================

static int check_emulator_files() {
    const char *emulator_files[] = {
        "/dev/socket/qemud", "/dev/qemu_pipe",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace", "/system/bin/qemu-props",
        NULL
    };

    for (int i = 0; emulator_files[i] != NULL; i++) {
        if (access(emulator_files[i], F_OK) == 0) {
            return 1;
        }
    }
    return 0;
}

JNIEXPORT jboolean JNICALL
Java_com_app_fortress_AppFortressPlugin_nativeIsEmulator(JNIEnv *env, jobject thiz) {
    return check_emulator_files();
}

// ============================================================================
// DEBUGGER DETECTION
// ============================================================================

static int check_traced() {
    char buf[512];
    int traced = 0;

    FILE *f = fopen("/proc/self/status", "r");
    if (f == NULL) return 0;

    while (fgets(buf, sizeof(buf), f)) {
        if (strncmp(buf, "TracerPid:", 10) == 0) {
            int tracer_pid = atoi(buf + 10);
            if (tracer_pid != 0) {
                traced = 1;
            }
            break;
        }
    }

    fclose(f);
    return traced;
}

static int check_ptrace() {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        return 1;
    }
    ptrace(PTRACE_DETACH, 0, NULL, NULL);
    return 0;
}

JNIEXPORT jboolean JNICALL
Java_com_app_fortress_AppFortressPlugin_nativeIsDebuggerAttached(JNIEnv *env, jobject thiz) {
    return check_traced() || check_ptrace();
}

// ============================================================================
// HOOKING DETECTION
// ============================================================================

static int phdr_callback(struct dl_phdr_info *info, size_t size, void *data) {
    int *found = (int *)data;

    const char *suspicious[] = {
        "frida", "xposed", "substrate", "cydia", "hook", "inject",
        NULL
    };

    if (info->dlpi_name != NULL) {
        for (int i = 0; suspicious[i] != NULL; i++) {
            if (strcasestr(info->dlpi_name, suspicious[i]) != NULL) {
                *found = 1;
                return 1;
            }
        }
    }

    return 0;
}

static int check_loaded_libraries() {
    int found = 0;
    dl_iterate_phdr(phdr_callback, &found);
    return found;
}

static int check_frida_port() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(27042);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    int result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);

    return (result == 0) ? 1 : 0;
}

static int check_maps_for_hooks() {
    FILE *f = fopen("/proc/self/maps", "r");
    if (f == NULL) return 0;

    char line[512];
    const char *suspicious[] = {"frida", "xposed", "substrate", NULL};

    while (fgets(line, sizeof(line), f)) {
        for (int i = 0; suspicious[i] != NULL; i++) {
            if (strcasestr(line, suspicious[i]) != NULL) {
                fclose(f);
                return 1;
            }
        }
    }

    fclose(f);
    return 0;
}

JNIEXPORT jboolean JNICALL
Java_com_app_fortress_AppFortressPlugin_nativeIsHooked(JNIEnv *env, jobject thiz) {
    return check_loaded_libraries() || check_frida_port() || check_maps_for_hooks();
}

// ============================================================================
// JNI INITIALIZATION
// ============================================================================

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    // Early anti-debug: attempt self-trace
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    return JNI_VERSION_1_6;
}
