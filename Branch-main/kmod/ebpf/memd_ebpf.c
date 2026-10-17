/* SPDX-License-Identifier: GPL-2.0 */
/* Userspace loader and CLI for memd_ebpf. */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "memd_ebpf.h"
#include "memd_offsets.h"

static struct bpf_object *obj;
static struct bpf_program *prog;
static int prog_fd = -1;

static int load_object(const char *path)
{
    int err;

    obj = bpf_object__open(path);
    if (!obj) {
        fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));
        return -1;
    }
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %s\n", strerror(-err));
        return -1;
    }
    prog = bpf_object__find_program_by_name(obj, "memd_ebpf_dispatch");
    if (!prog) {
        fprintf(stderr, "program memd_ebpf_dispatch not found\n");
        return -1;
    }
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "invalid program fd\n");
        return -1;
    }
    return 0;
}

static int run_req(struct memd_ebpf_req *req)
{
    LIBBPF_OPTS(bpf_test_run_opts, topts,
                .data_in = req,
                .data_size_in = sizeof(*req),
                .data_out = req,
                .data_size_out = sizeof(*req),
                .repeat = 1);
    int err = bpf_prog_test_run_opts(prog_fd, &topts);
    if (err) {
        fprintf(stderr, "BPF_RUN failed: %s\n", strerror(-err));
        return -1;
    }
    if (topts.retval < 0) {
        fprintf(stderr, "program returned %d\n", topts.retval);
        return topts.retval;
    }
    return req->status;
}

static void hexdump(const void *p, size_t n)
{
    const unsigned char *b = p;
    size_t i, j;
    for (i = 0; i < n; i += 16) {
        printf("%08zx  ", i);
        for (j = 0; j < 16; j++) {
            if (i + j < n)
                printf("%02x ", b[i + j]);
            else
                printf("   ");
        }
        printf(" |");
        for (j = 0; j < 16 && i + j < n; j++) {
            unsigned char c = b[i + j];
            printf("%c", (c >= 32 && c < 127) ? c : '.');
        }
        printf("|\n");
    }
}

static int cmd_ping(void)
{
    struct memd_ebpf_req req;
    memset(&req, 0, sizeof(req));
    req.op = MEMD_EBPF_OP_PING;
    int rc = run_req(&req);
    printf("ping: status=%d\n", rc);
    return rc;
}

static int cmd_kread(unsigned long addr, size_t len)
{
    void *buf = calloc(1, len ? len : 1);
    if (!buf) {
        perror("calloc");
        return -1;
    }
    struct memd_ebpf_req req;
    memset(&req, 0, sizeof(req));
    req.op = MEMD_EBPF_OP_KREAD;
    req.addr = addr;
    req.len = len;
    req.user_buf = (unsigned long)buf;
    int rc = run_req(&req);
    if (rc == 0) {
        printf("read %u bytes from 0x%lx:\n", req.done, addr);
        hexdump(buf, req.done);
    } else {
        fprintf(stderr, "kread failed: %d (done=%u)\n", rc, req.done);
    }
    free(buf);
    return rc;
}

static int cmd_uread(unsigned long addr, size_t len)
{
    void *buf = calloc(1, len ? len : 1);
    if (!buf) {
        perror("calloc");
        return -1;
    }
    struct memd_ebpf_req req;
    memset(&req, 0, sizeof(req));
    req.op = MEMD_EBPF_OP_UREAD;
    req.addr = addr;
    req.len = len;
    req.user_buf = (unsigned long)buf;
    int rc = run_req(&req);
    if (rc == 0) {
        printf("read %u bytes from 0x%lx:\n", req.done, addr);
        hexdump(buf, req.done);
    } else {
        fprintf(stderr, "uread failed: %d (done=%u)\n", rc, req.done);
    }
    free(buf);
    return rc;
}

static int cmd_uwrite(unsigned long addr, const char *hex)
{
    size_t hexlen = strlen(hex);
    size_t nbytes = hexlen / 2;
    unsigned char *buf = calloc(1, nbytes ? nbytes : 1);
    if (!buf) {
        perror("calloc");
        return -1;
    }
    for (size_t i = 0; i < nbytes; i++) {
        unsigned int v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) {
            fprintf(stderr, "bad hex at %zu\n", i);
            free(buf);
            return -1;
        }
        buf[i] = (unsigned char)v;
    }
    struct memd_ebpf_req req;
    memset(&req, 0, sizeof(req));
    req.op = MEMD_EBPF_OP_UWRITE;
    req.addr = addr;
    req.len = nbytes;
    req.user_buf = (unsigned long)buf;
    int rc = run_req(&req);
    if (rc == 0)
        printf("wrote %u bytes to 0x%lx\n", req.done, addr);
    else
        fprintf(stderr, "uwrite failed: %d (done=%u)\n", rc, req.done);
    free(buf);
    return rc;
}

static int cmd_offset(unsigned int sid, unsigned int fid)
{
    struct memd_ebpf_req req;
    memset(&req, 0, sizeof(req));
    req.op = MEMD_EBPF_OP_OFFSET;
    req.struct_id = sid;
    req.field_id = fid;
    int rc = run_req(&req);
    if (rc == 0)
        printf("%s.%s offset = %llu\n", memd_struct_name(sid),
               memd_field_name(sid, fid), (unsigned long long)req.offset_out);
    else
        fprintf(stderr, "offset failed: %d\n", rc);
    return rc;
}

static int cmd_kread_str(unsigned long addr, size_t max)
{
    char *buf = calloc(1, max ? max : 257);
    if (!buf) {
        perror("calloc");
        return -1;
    }
    struct memd_ebpf_req req;
    memset(&req, 0, sizeof(req));
    req.op = MEMD_EBPF_OP_KREAD_STR;
    req.addr = addr;
    req.len = max;
    req.user_buf = (unsigned long)buf;
    int rc = run_req(&req);
    if (rc == 0)
        printf("kstr @0x%lx: %s (len=%u)\n", addr, buf, req.done);
    else
        fprintf(stderr, "kread_str failed: %d\n", rc);
    free(buf);
    return rc;
}

static int cmd_uread_str(unsigned long addr, size_t max)
{
    char *buf = calloc(1, max ? max : 257);
    if (!buf) {
        perror("calloc");
        return -1;
    }
    struct memd_ebpf_req req;
    memset(&req, 0, sizeof(req));
    req.op = MEMD_EBPF_OP_UREAD_STR;
    req.addr = addr;
    req.len = max;
    req.user_buf = (unsigned long)buf;
    int rc = run_req(&req);
    if (rc == 0)
        printf("ustr @0x%lx: %s (len=%u)\n", addr, buf, req.done);
    else
        fprintf(stderr, "uread_str failed: %d\n", rc);
    free(buf);
    return rc;
}

static int cmd_memset(unsigned long addr, size_t len, unsigned int val)
{
    struct memd_ebpf_req req;
    memset(&req, 0, sizeof(req));
    req.op = MEMD_EBPF_OP_MEMSET_USER;
    req.addr = addr;
    req.len = len;
    req.aux = val;
    int rc = run_req(&req);
    if (rc == 0)
        printf("memset %zu bytes at 0x%lx = 0x%02x\n", len, addr, val);
    else
        fprintf(stderr, "memset failed: %d\n", rc);
    return rc;
}

static int cmd_crc32(unsigned long addr, size_t len)
{
    struct memd_ebpf_req req;
    memset(&req, 0, sizeof(req));
    req.op = MEMD_EBPF_OP_CRC32;
    req.addr = addr;
    req.len = len;
    int rc = run_req(&req);
    if (rc == 0)
        printf("crc32(0x%lx, %zu) = 0x%08llx\n", addr, len,
               (unsigned long long)req.offset_out);
    else
        fprintf(stderr, "crc32 failed: %d\n", rc);
    return rc;
}

static int cmd_strlen(unsigned long addr, size_t max)
{
    struct memd_ebpf_req req;
    memset(&req, 0, sizeof(req));
    req.op = MEMD_EBPF_OP_STRLEN_USER;
    req.addr = addr;
    req.len = max;
    int rc = run_req(&req);
    if (rc == 0)
        printf("strlen(0x%lx) = %llu\n", addr, (unsigned long long)req.offset_out);
    else
        fprintf(stderr, "strlen failed: %d\n", rc);
    return rc;
}

static void usage(const char *p)
{
    fprintf(stderr,
        "Usage: %s -o <file.bpf.o> <command>\n"
        "  ping\n"
        "  kread <addr> <len>\n"
        "  uread <addr> <len>\n"
        "  uwrite <addr> <hex>\n"
        "  offset <struct_id> <field_id>\n"
        "  kread_str <addr> <max>\n"
        "  uread_str <addr> <max>\n"
        "  memset <addr> <len> <val>\n"
        "  crc32 <addr> <len>\n"
        "  strlen <addr> <max>\n",
        p);
}

int main(int argc, char **argv)
{
    const char *objpath = "memd_ebpf.bpf.o";
    int opt;
    while ((opt = getopt(argc, argv, "o:h")) != -1) {
        switch (opt) {
        case 'o': objpath = optarg; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }
    if (optind >= argc) {
        usage(argv[0]);
        return 1;
    }
    if (load_object(objpath) != 0)
        return 1;

    const char *cmd = argv[optind];
    if (strcmp(cmd, "ping") == 0) {
        return cmd_ping() < 0 ? 1 : 0;
    } else if (strcmp(cmd, "kread") == 0) {
        if (optind + 2 >= argc) { usage(argv[0]); return 1; }
        return cmd_kread(strtoul(argv[optind + 1], NULL, 0),
                         strtoul(argv[optind + 2], NULL, 0)) < 0 ? 1 : 0;
    } else if (strcmp(cmd, "uread") == 0) {
        if (optind + 2 >= argc) { usage(argv[0]); return 1; }
        return cmd_uread(strtoul(argv[optind + 1], NULL, 0),
                         strtoul(argv[optind + 2], NULL, 0)) < 0 ? 1 : 0;
    } else if (strcmp(cmd, "uwrite") == 0) {
        if (optind + 2 >= argc) { usage(argv[0]); return 1; }
        return cmd_uwrite(strtoul(argv[optind + 1], NULL, 0),
                          argv[optind + 2]) < 0 ? 1 : 0;
    } else if (strcmp(cmd, "offset") == 0) {
        if (optind + 2 >= argc) { usage(argv[0]); return 1; }
        return cmd_offset((unsigned int)strtoul(argv[optind + 1], NULL, 0),
                          (unsigned int)strtoul(argv[optind + 2], NULL, 0)) < 0 ? 1 : 0;
    } else if (strcmp(cmd, "kread_str") == 0) {
        if (optind + 2 >= argc) { usage(argv[0]); return 1; }
        return cmd_kread_str(strtoul(argv[optind + 1], NULL, 0),
                             strtoul(argv[optind + 2], NULL, 0)) < 0 ? 1 : 0;
    } else if (strcmp(cmd, "uread_str") == 0) {
        if (optind + 2 >= argc) { usage(argv[0]); return 1; }
        return cmd_uread_str(strtoul(argv[optind + 1], NULL, 0),
                             strtoul(argv[optind + 2], NULL, 0)) < 0 ? 1 : 0;
    } else if (strcmp(cmd, "memset") == 0) {
        if (optind + 3 >= argc) { usage(argv[0]); return 1; }
        return cmd_memset(strtoul(argv[optind + 1], NULL, 0),
                          strtoul(argv[optind + 2], NULL, 0),
                          (unsigned int)strtoul(argv[optind + 3], NULL, 0)) < 0 ? 1 : 0;
    } else if (strcmp(cmd, "crc32") == 0) {
        if (optind + 2 >= argc) { usage(argv[0]); return 1; }
        return cmd_crc32(strtoul(argv[optind + 1], NULL, 0),
                         strtoul(argv[optind + 2], NULL, 0)) < 0 ? 1 : 0;
    } else if (strcmp(cmd, "strlen") == 0) {
        if (optind + 2 >= argc) { usage(argv[0]); return 1; }
        return cmd_strlen(strtoul(argv[optind + 1], NULL, 0),
                          strtoul(argv[optind + 2], NULL, 0)) < 0 ? 1 : 0;
    } else {
        fprintf(stderr, "unknown command: %s\n", cmd);
        usage(argv[0]);
        return 1;
    }
}