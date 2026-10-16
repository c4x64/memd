/* memd_bridge.c — thin JNI translation layer for the DSU MemdDriver.
 *
 * Each entry point validates its Java arguments (null / empty / range),
 * fills the matching struct declared in client.h, issues exactly one
 * ioctl() on the caller-supplied driver fd, and returns a status int.
 * Expected driver errors come back as negative -errno codes; this file
 * never throws Java exceptions for them.
 *
 * client.h is included by relative path and never copied, so ioctl
 * numbers and struct layouts stay single-sourced with the driver.
 */

#include <jni.h>

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include "memd_bridge.h"
#include "../client.h"

JNIEXPORT jint JNICALL
Java_com_lxgr_dsu_MemdDriver_getVersion(JNIEnv *env, jclass clazz,
                                        jint fd, jintArray out)
{
    struct memd_version_cmd cmd;
    jint buf[MEMD_BRIDGE_VERSION_OUT_LEN];
    int r;

    (void)clazz;

    if (env == NULL || out == NULL) {
        return MEMD_BRIDGE_EINVAL;
    }
    if (fd < 0) {
        return MEMD_BRIDGE_EINVAL;
    }
    if ((*env)->GetArrayLength(env, out) < MEMD_BRIDGE_VERSION_OUT_LEN) {
        return MEMD_BRIDGE_EINVAL;
    }
    memset(&cmd, 0, sizeof(cmd));
    cmd.abi = MEMD_ABI_VERSION;
    r = ioctl(fd, MEMD_IOCTL_VERSION, &cmd);
    if (r < 0) {
        return -errno;
    }
    if (cmd.result < 0) {
        return cmd.result;
    }
    buf[0] = (jint)cmd.major;
    buf[1] = (jint)cmd.minor;
    buf[2] = (jint)cmd.patch;
    buf[3] = (jint)cmd.flags;
    buf[4] = (jint)cmd.gen;
    (*env)->SetIntArrayRegion(env, out, 0, MEMD_BRIDGE_VERSION_OUT_LEN, buf);
    return MEMD_BRIDGE_OK;
}

JNIEXPORT jint JNICALL
Java_com_lxgr_dsu_MemdDriver_getLearnStatus(JNIEnv *env, jclass clazz,
                                            jint fd, jintArray out)
{
    struct memd_learn_status_cmd cmd;
    jint buf[MEMD_BRIDGE_LEARN_OUT_LEN];
    int r;

    (void)clazz;

    if (env == NULL || out == NULL) {
        return MEMD_BRIDGE_EINVAL;
    }
    if (fd < 0) {
        return MEMD_BRIDGE_EINVAL;
    }
    if ((*env)->GetArrayLength(env, out) < MEMD_BRIDGE_LEARN_OUT_LEN) {
        return MEMD_BRIDGE_EINVAL;
    }
    memset(&cmd, 0, sizeof(cmd));
    r = ioctl(fd, MEMD_IOCTL_LEARN_STATUS, &cmd);
    if (r < 0) {
        return -errno;
    }
    if (cmd.result < 0) {
        return cmd.result;
    }
    buf[0] = (jint)cmd.gen;
    buf[1] = (jint)cmd.t_pid;
    buf[2] = (jint)cmd.t_tgid;
    buf[3] = (jint)cmd.t_mm;
    buf[4] = (jint)cmd.t_cred;
    buf[5] = (jint)cmd.v_start;
    buf[6] = (jint)cmd.v_end;
    buf[7] = (jint)cmd.v_flags;
    buf[8] = (jint)cmd.m_pgd;
    buf[9] = (jint)cmd.mask;
    (*env)->SetIntArrayRegion(env, out, 0, MEMD_BRIDGE_LEARN_OUT_LEN, buf);
    return MEMD_BRIDGE_OK;
}

JNIEXPORT jint JNICALL
Java_com_lxgr_dsu_MemdDriver_bootstrap(JNIEnv *env, jclass clazz,
                                       jint fd, jlong filpOpen,
                                       jlong kernelRead, jlong filpClose)
{
    struct memd_bootstrap_cmd cmd;
    int r;

    (void)clazz;

    if (env == NULL) {
        return MEMD_BRIDGE_EINVAL;
    }
    if (fd < 0) {
        return MEMD_BRIDGE_EINVAL;
    }
    if (filpOpen <= 0 || kernelRead <= 0 || filpClose <= 0) {
        return MEMD_BRIDGE_EINVAL;
    }
    memset(&cmd, 0, sizeof(cmd));
    cmd.filp_open = (uint64_t)filpOpen;
    cmd.kernel_read = (uint64_t)kernelRead;
    cmd.filp_close = (uint64_t)filpClose;
    r = ioctl(fd, MEMD_IOCTL_BOOTSTRAP, &cmd);
    if (r < 0) {
        return -errno;
    }
    return cmd.result;
}

JNIEXPORT jint JNICALL
Java_com_lxgr_dsu_MemdDriver_loadSo(JNIEnv *env, jclass clazz,
                                    jint fd, jint pid,
                                    jstring path, jstring entry,
                                    jboolean su, jboolean ephemeral,
                                    jlongArray outHandle, jintArray outEntry)
{
    struct memd_loadso_cmd cmd;
    const char *pathChars;
    const char *entryChars;
    jsize pathLen;
    jsize entryLen;
    jlong handleVal;
    jint entryVal;
    unsigned long req;
    int r;

    (void)clazz;
    pathChars = NULL;
    entryChars = NULL;

    if (env == NULL) {
        return MEMD_BRIDGE_EINVAL;
    }
    if (fd < 0 || pid <= 0) {
        return MEMD_BRIDGE_EINVAL;
    }
    if (path == NULL || outHandle == NULL) {
        return MEMD_BRIDGE_EINVAL;
    }
    if ((*env)->GetArrayLength(env, outHandle) < MEMD_BRIDGE_HANDLE_OUT_LEN) {
        return MEMD_BRIDGE_EINVAL;
    }
    if (outEntry != NULL &&
        (*env)->GetArrayLength(env, outEntry) < MEMD_BRIDGE_ENTRY_OUT_LEN) {
        return MEMD_BRIDGE_EINVAL;
    }

    memset(&cmd, 0, sizeof(cmd));
    cmd.pid = (pid_t)pid;

    pathLen = (*env)->GetStringUTFLength(env, path);
    if (pathLen <= 0) {
        return MEMD_BRIDGE_EINVAL;
    }
    if (pathLen >= (jsize)sizeof(cmd.path)) {
        return MEMD_BRIDGE_ENAMETOOLONG;
    }
    pathChars = (*env)->GetStringUTFChars(env, path, NULL);
    if (pathChars == NULL) {
        return -ENOMEM; /* OOM: JVM holds a pending OutOfMemoryError. */
    }
    if (pathChars[0] != '/') {
        (*env)->ReleaseStringUTFChars(env, path, pathChars);
        return MEMD_BRIDGE_EINVAL;
    }
    memcpy(cmd.path, pathChars, (size_t)pathLen + 1u);
    (*env)->ReleaseStringUTFChars(env, path, pathChars);
    pathChars = NULL;

    /* A null or empty entry means "dlopen only, skip the entry call",
     * matching client.h. A non-empty entry must be a bare symbol name. */
    if (entry != NULL) {
        entryLen = (*env)->GetStringUTFLength(env, entry);
        if (entryLen < 0) {
            return MEMD_BRIDGE_EINVAL;
        }
        if (entryLen >= (jsize)sizeof(cmd.entry)) {
            return MEMD_BRIDGE_EINVAL;
        }
        if (entryLen > 0) {
            entryChars = (*env)->GetStringUTFChars(env, entry, NULL);
            if (entryChars == NULL) {
                return -ENOMEM;
            }
            if (strchr(entryChars, '/') != NULL) {
                (*env)->ReleaseStringUTFChars(env, entry, entryChars);
                return MEMD_BRIDGE_EINVAL;
            }
            memcpy(cmd.entry, entryChars, (size_t)entryLen + 1u);
            (*env)->ReleaseStringUTFChars(env, entry, entryChars);
            entryChars = NULL;
        }
    }

    if (ephemeral) {
        cmd.flags = MEMD_LOADSO_EPHEMERAL;
    }
    if (su) {
        req = MEMD_IOCTL_LOAD_SOSUTOAPP;
    } else {
        req = MEMD_IOCTL_LOAD_SOTOAPP;
    }
    r = ioctl(fd, req, &cmd);
    if (r < 0) {
        return -errno;
    }
    if (cmd.result < 0) {
        return cmd.result;
    }
    handleVal = (jlong)cmd.handle;
    (*env)->SetLongArrayRegion(env, outHandle, 0,
                               MEMD_BRIDGE_HANDLE_OUT_LEN, &handleVal);
    if (outEntry != NULL) {
        entryVal = (jint)cmd.entry_result;
        (*env)->SetIntArrayRegion(env, outEntry, 0,
                                  MEMD_BRIDGE_ENTRY_OUT_LEN, &entryVal);
    }
    return MEMD_BRIDGE_OK;
}

JNIEXPORT jint JNICALL
Java_com_lxgr_dsu_MemdDriver_unloadSo(JNIEnv *env, jclass clazz,
                                      jint fd, jint pid, jlong handle)
{
    struct memd_loadso_unload_cmd cmd;
    int r;

    (void)clazz;

    if (env == NULL) {
        return MEMD_BRIDGE_EINVAL;
    }
    if (fd < 0 || pid <= 0 || handle <= 0) {
        return MEMD_BRIDGE_EINVAL;
    }
    memset(&cmd, 0, sizeof(cmd));
    cmd.pid = (pid_t)pid;
    cmd.handle = (uintptr_t)handle;
    r = ioctl(fd, MEMD_IOCTL_LOADSO_UNLOAD, &cmd);
    if (r < 0) {
        return -errno;
    }
    return cmd.result;
}
