/*
 * gate_watcher.c — fanotify FAN_OPEN_PERM watcher for GATE-M
 *
 * Uses Linux fanotify(7) with FAN_OPEN_PERM to intercept open() syscalls
 * at the kernel level. The kernel holds the calling process's syscall until
 * we write FAN_ALLOW or FAN_DENY back to the fanotify fd.
 *
 * Flow:
 *   agent open("evil.py", O_WRONLY)
 *     → kernel fires FAN_OPEN_PERM event
 *     → our thread reads event, resolves path
 *     → if path is outside watched_root: FAN_ALLOW immediately (no Python call)
 *     → if path is inside watched_root: call Python verdict_cb(path, pid, is_write)
 *     → Python returns 1 (allow) or 0 (deny)
 *     → we write FAN_ALLOW or FAN_DENY
 *     → kernel resumes or fails the agent's syscall — atomically
 *
 * Requires: CAP_SYS_ADMIN (or a suitable user namespace)
 * Compile:  gcc -Wall -O2 -fPIC -shared -o gate_watcher.so gate_watcher.c -lpthread
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <limits.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Python callback: path, pid, is_write → 1=allow, 0=deny */
typedef int (*verdict_cb_t)(const char *path, pid_t pid, int is_write);

static int          fan_fd        = -1;
static pthread_t    watcher_tid;
static volatile int running       = 0;
static verdict_cb_t verdict_cb    = NULL;
static pid_t        own_pid;
static char         watched_root[PATH_MAX];
static size_t       watched_root_len = 0;

/* Write a fanotify response; ignore return value intentionally —
 * if the write fails there is nothing meaningful we can do and we
 * must not stall the event loop. */
static inline void send_response(struct fanotify_response *r)
{
    (void)write(fan_fd, r, sizeof(*r));
}

/* ── path resolution ──────────────────────────────────────────────────────── */

static int resolve_path(int event_fd, char *out, size_t outsize)
{
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", event_fd);
    ssize_t n = readlink(proc_path, out, outsize - 1);
    if (n < 0)
        return -1;
    out[n] = '\0';
    return 0;
}

/* ── fanotify event loop (runs in background thread) ─────────────────────── */

static void *watcher_loop(void *arg)
{
    (void)arg;

    /*
     * Buffer sized to hold multiple events. fanotify events vary in size;
     * 4096 bytes is enough for ~50 events at a time.
     */
    char buf[4096]
        __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));

    while (running) {
        ssize_t len = read(fan_fd, buf, sizeof(buf));

        if (len < 0) {
            if (errno == EINTR)
                continue;
            /* fd closed by gate_stop() */
            break;
        }

        struct fanotify_event_metadata *ev =
            (struct fanotify_event_metadata *)buf;

        while (FAN_EVENT_OK(ev, len)) {

            /* Sanity: reject stale ABI */
            if (ev->vers != FANOTIFY_METADATA_VERSION) {
                if (ev->fd >= 0) close(ev->fd);
                ev = FAN_EVENT_NEXT(ev, len);
                continue;
            }

            /* We only registered for FAN_OPEN_PERM */
            if (!(ev->mask & FAN_OPEN_PERM)) {
                if (ev->fd >= 0) close(ev->fd);
                ev = FAN_EVENT_NEXT(ev, len);
                continue;
            }

            struct fanotify_response resp;
            resp.fd       = ev->fd;
            resp.response = FAN_ALLOW; /* default: fail open */

            /* Never block our own process — would deadlock */
            if (ev->pid == own_pid) {
                send_response(&resp);
                close(ev->fd);
                ev = FAN_EVENT_NEXT(ev, len);
                continue;
            }

            /* Resolve actual filesystem path from the event fd */
            char path[PATH_MAX];
            if (resolve_path(ev->fd, path, sizeof(path)) < 0) {
                /* Can't resolve → fail open, never deadlock */
                send_response(&resp);
                close(ev->fd);
                ev = FAN_EVENT_NEXT(ev, len);
                continue;
            }

            /* Fast prefix filter: auto-allow anything outside project root.
             * FAN_MARK_MOUNT marks the whole filesystem; without this filter
             * we'd call Python for every open() on the system. */
            if (watched_root_len > 0 &&
                strncmp(path, watched_root, watched_root_len) != 0) {
                send_response(&resp);
                close(ev->fd);
                ev = FAN_EVENT_NEXT(ev, len);
                continue;
            }

            /* Determine access mode: read or write */
            int flags   = fcntl(ev->fd, F_GETFL);
            int is_write = (flags >= 0) &&
                           ((flags & O_ACCMODE) == O_WRONLY ||
                            (flags & O_ACCMODE) == O_RDWR);

            /* Call Python verdict callback.
             * ctypes CFUNCTYPE acquires the GIL automatically. */
            if (verdict_cb) {
                int allow = verdict_cb(path, ev->pid, is_write);
                resp.response = allow ? FAN_ALLOW : FAN_DENY;
            }

            send_response(&resp);
            close(ev->fd);

            ev = FAN_EVENT_NEXT(ev, len);
        }
    }

    return NULL;
}

/* ── public API ───────────────────────────────────────────────────────────── */

/*
 * gate_check_privileges()
 *
 * Returns 0 if fanotify is usable (CAP_SYS_ADMIN present), -errno otherwise.
 * Call this before gate_init() to decide whether to use fanotify or fall back.
 */
int gate_check_privileges(void)
{
    int fd = fanotify_init(FAN_CLASS_CONTENT, O_RDONLY);
    if (fd < 0)
        return -errno;
    close(fd);
    return 0;
}

/*
 * gate_init(watch_path)
 *
 * Opens the fanotify fd and marks the mount containing watch_path.
 * Returns 0 on success, -errno on failure.
 */
int gate_init(const char *watch_path)
{
    own_pid = getpid();

    strncpy(watched_root, watch_path, sizeof(watched_root) - 1);
    watched_root[sizeof(watched_root) - 1] = '\0';
    watched_root_len = strlen(watched_root);

    /* Strip trailing slash for consistent prefix matching */
    while (watched_root_len > 1 && watched_root[watched_root_len - 1] == '/') {
        watched_root[--watched_root_len] = '\0';
    }

    fan_fd = fanotify_init(FAN_CLASS_CONTENT, O_RDONLY | O_LARGEFILE);
    if (fan_fd < 0)
        return -errno;

    /*
     * FAN_MARK_MOUNT: mark the mount containing watch_path.
     * We use the C-side prefix filter so only project_root paths
     * reach the Python callback.
     */
    if (fanotify_mark(fan_fd,
                      FAN_MARK_ADD | FAN_MARK_MOUNT,
                      FAN_OPEN_PERM,
                      AT_FDCWD,
                      watch_path) < 0) {
        int err = errno;
        close(fan_fd);
        fan_fd = -1;
        return -err;
    }

    return 0;
}

/*
 * gate_start(callback)
 *
 * Launches the background watcher thread. The thread calls `callback` for
 * every open() inside the watched path. callback must be thread-safe.
 * Returns 0 on success, -errno on failure.
 */
int gate_start(verdict_cb_t callback)
{
    if (fan_fd < 0)
        return -EINVAL;

    verdict_cb = callback;
    running    = 1;

    int rc = pthread_create(&watcher_tid, NULL, watcher_loop, NULL);
    if (rc != 0) {
        running = 0;
        return -rc;
    }
    return 0;
}

/*
 * gate_stop()
 *
 * Signals the watcher thread to stop and waits for it to exit.
 * Safe to call multiple times.
 */
void gate_stop(void)
{
    running = 0;
    if (fan_fd >= 0) {
        close(fan_fd);
        fan_fd = -1;
    }
    /* pthread_join is safe to call even if thread exited */
    pthread_join(watcher_tid, NULL);
}
