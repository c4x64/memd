/* memd_bridge.h — JNI contract for the DSU app's MemdDriver bridge.
 *
 * Thin translation layer only: the matching .c file validates Java
 * arguments, fills the structs declared in client.h, and issues one
 * ioctl() per call. No stealth, no concealment, no persistence.
 */

#ifndef MEMD_BRIDGE_H
#define MEMD_BRIDGE_H

#include <jni.h>

/* Status convention: 0 ok, negative -errno (validation, ioctl, or the
 * driver-reported cmd.result). Expected driver errors are returned,
 * never thrown as Java exceptions. */
#define MEMD_BRIDGE_OK           0
#define MEMD_BRIDGE_EINVAL       (-22)  /* bad fd, null/empty arg, range */
#define MEMD_BRIDGE_ENAMETOOLONG (-36)  /* .so path does not fit 256 B */

/* Minimum Java array lengths for the output parameters. */
#define MEMD_BRIDGE_VERSION_OUT_LEN 5  /* major, minor, patch, flags, gen */
#define MEMD_BRIDGE_LEARN_OUT_LEN   10 /* gen, 8 offsets, mask */
#define MEMD_BRIDGE_HANDLE_OUT_LEN  1  /* dlopen handle */
#define MEMD_BRIDGE_ENTRY_OUT_LEN   1  /* entry return value */

JNIEXPORT jint JNICALL
Java_com_lxgr_dsu_MemdDriver_getVersion(JNIEnv *env, jclass clazz,
                                        jint fd, jintArray out);

JNIEXPORT jint JNICALL
Java_com_lxgr_dsu_MemdDriver_getLearnStatus(JNIEnv *env, jclass clazz,
                                            jint fd, jintArray out);

JNIEXPORT jint JNICALL
Java_com_lxgr_dsu_MemdDriver_bootstrap(JNIEnv *env, jclass clazz,
                                       jint fd, jlong filpOpen,
                                       jlong kernelRead, jlong filpClose);

JNIEXPORT jint JNICALL
Java_com_lxgr_dsu_MemdDriver_loadSo(JNIEnv *env, jclass clazz,
                                    jint fd, jint pid,
                                    jstring path, jstring entry,
                                    jboolean su, jboolean ephemeral,
                                    jlongArray outHandle, jintArray outEntry);

JNIEXPORT jint JNICALL
Java_com_lxgr_dsu_MemdDriver_unloadSo(JNIEnv *env, jclass clazz,
                                      jint fd, jint pid, jlong handle);

#endif /* MEMD_BRIDGE_H */
