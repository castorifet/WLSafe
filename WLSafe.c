

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <linux/fanotify.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>

#define WHITELIST_PATH "/etc/whitelist"
#define MAX_LINE 4096

typedef struct {
    dev_t dev;
    ino_t ino;
    char *path;   
} WLEntryFile;

typedef struct {
    char *dir;   
    size_t len;
} WLEntryDir;

typedef struct {
    char *dir;      
    size_t dirlen;
    char *pattern;    
} WLEntryGlob;

static WLEntryFile *wl_files = NULL; size_t wl_files_count = 0;
static WLEntryDir  *wl_dirs  = NULL; size_t wl_dirs_count  = 0;
static WLEntryGlob *wl_globs = NULL; size_t wl_globs_count = 0;

static int fan_fd = -1;
static volatile sig_atomic_t want_reload = 0;

static void stamp(FILE *fp) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm; localtime_r(&ts.tv_sec, &tm);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    fprintf(fp, "%s.%03ld killer[%d]: ", buf, ts.tv_nsec/1000000, (int)getpid());
}
static void log_msg(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    stamp(stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    fflush(stderr);
    va_end(ap);
}

static char *trim(char *s) {
    if (!s) return s;
    while (*s==' '||*s=='\t'||*s=='\r'||*s=='\n') s++;
    size_t n = strlen(s);
    while (n && (s[n-1]==' '||s[n-1]=='\t'||s[n-1]=='\r'||s[n-1]=='\n')) s[--n] = '\0';
    return s;
}

static void free_whitelist(void) {
    if (wl_files) {
        for (size_t i=0;i<wl_files_count;i++) free(wl_files[i].path);
        free(wl_files); wl_files=NULL; wl_files_count=0;
    }
    if (wl_dirs) {
        for (size_t i=0;i<wl_dirs_count;i++) free(wl_dirs[i].dir);
        free(wl_dirs); wl_dirs=NULL; wl_dirs_count=0;
    }
    if (wl_globs) {
        for (size_t i=0;i<wl_globs_count;i++) { free(wl_globs[i].dir); free(wl_globs[i].pattern); }
        free(wl_globs); wl_globs=NULL; wl_globs_count=0;
    }
}

static int cmp_file(const void *a, const void *b) {
    const WLEntryFile *x=a, *y=b;
    if (x->dev < y->dev) return -1;
    if (x->dev > y->dev) return  1;
    if (x->ino < y->ino) return -1;
    if (x->ino > y->ino) return  1;
    return 0;
}
static int cmp_dir(const void *a, const void *b) {
    const WLEntryDir *x=a, *y=b;
    if (x->len > y->len) return -1;
    if (x->len < y->len) return  1;
    return strcmp(x->dir, y->dir);
}

static bool has_glob_chars(const char *s) {
    return strpbrk(s, "*?[") != NULL; 
}

static int add_dir_entry(const char *canon_dir) {
    size_t L = strlen(canon_dir);
    char *buf = malloc(L + 2);
    if (!buf) return -1;
    strcpy(buf, canon_dir);
    if (buf[L-1] != '/') { buf[L] = '/'; buf[L+1] = '\0'; L++; }
    WLEntryDir *tmp = realloc(wl_dirs, (wl_dirs_count+1)*sizeof(WLEntryDir));
    if (!tmp) { free(buf); return -1; }
    wl_dirs = tmp;
    wl_dirs[wl_dirs_count].dir = buf;
    wl_dirs[wl_dirs_count].len = L;
    wl_dirs_count++;
    return 0;
}

static int add_file_entry(const char *canon_path, const struct stat *st) {
    WLEntryFile *tmp = realloc(wl_files, (wl_files_count+1)*sizeof(WLEntryFile));
    if (!tmp) return -1;
    wl_files = tmp;
    wl_files[wl_files_count].dev = st->st_dev;
    wl_files[wl_files_count].ino = st->st_ino;
    wl_files[wl_files_count].path = strndup(canon_path, PATH_MAX);
    if (!wl_files[wl_files_count].path) return -1;
    wl_files_count++;
    return 0;
}

static int add_glob_entry(const char *canon_dir, const char *basename_pattern) {
    size_t L = strlen(canon_dir);
    char *d = malloc(L + 2);
    if (!d) return -1;
    strcpy(d, canon_dir);
    if (d[L-1] != '/') { d[L] = '/'; d[L+1] = '\0'; L++; }
    char *p = strdup(basename_pattern);
    if (!p) { free(d); return -1; }
    WLEntryGlob *tmp = realloc(wl_globs, (wl_globs_count+1)*sizeof(WLEntryGlob));
    if (!tmp) { free(d); free(p); return -1; }
    wl_globs = tmp;
    wl_globs[wl_globs_count].dir = d;
    wl_globs[wl_globs_count].dirlen = L;
    wl_globs[wl_globs_count].pattern = p;
    wl_globs_count++;
    return 0;
}

static int load_whitelist(void) {
    FILE *f = fopen(WHITELIST_PATH, "r");
    if (!f) { log_msg("Cannot open %s: %s", WHITELIST_PATH, strerror(errno)); return -1; }

    free_whitelist();

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        char *p = trim(line);
        if (!*p || *p=='#') continue;
        if (p[0] != '/') { log_msg("Skipping non-absolute entry: %s", p); continue; }

        bool trailing_star = false;
        size_t len = strlen(p);
        if (len >= 2 && p[len-1]=='*' && p[len-2]=='/') {
            trailing_star = true;
            p[len-2] = '\0'; 
        }

        bool is_glob = false;
        char *last_slash = strrchr(p, '/');
        if (!last_slash) { log_msg("Skipping malformed entry: %s", p); continue; }
        char *dir_part = p; *last_slash = '\0';
        char *base_part = last_slash + 1;

        if (!trailing_star && has_glob_chars(base_part)) {
            if (has_glob_chars(dir_part)) {
                log_msg("Skipping glob with wildcard in directory: %s/*%s (not supported)", dir_part, base_part);
                *last_slash = '/';
                continue;
            }
            is_glob = true;
        }
        *last_slash = '/';

        if (is_glob) {
            char dirbuf[PATH_MAX];
            char save = *last_slash; *last_slash = '\0';
            if (!realpath(dir_part, dirbuf)) {
                log_msg("Skipping %s (realpath dir failed: %s)", p, strerror(errno));
                *last_slash = save;
                continue;
            }
            *last_slash = save;
            if (add_glob_entry(dirbuf, base_part) != 0) {
                log_msg("OOM adding glob %s (dir=%s, pat=%s)", p, dirbuf, base_part);
                fclose(f); return -1;
            }
            continue;
        }

        char resolved[PATH_MAX];
        if (!realpath(p, resolved)) {
            log_msg("Skipping %s (realpath failed: %s)", p, strerror(errno));
            continue;
        }

        struct stat st;
        if (stat(resolved, &st) != 0) {
            log_msg("Skipping %s (stat failed: %s)", resolved, strerror(errno));
            continue;
        }

        if (trailing_star || S_ISDIR(st.st_mode)) {
            if (add_dir_entry(resolved) != 0) { log_msg("OOM adding dir %s", resolved); fclose(f); return -1; }
        } else {
            if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
                log_msg("Skipping non-regular file: %s", resolved);
                continue;
            }
            if (add_file_entry(resolved, &st) != 0) { log_msg("OOM adding file %s", resolved); fclose(f); return -1; }
        }
    }
    fclose(f);

    if (wl_files_count) qsort(wl_files, wl_files_count, sizeof(WLEntryFile), cmp_file);
    if (wl_dirs_count)  qsort(wl_dirs,  wl_dirs_count,  sizeof(WLEntryDir),  cmp_dir);

    log_msg("Loaded whitelist: %zu files, %zu dirs, %zu globs", wl_files_count, wl_dirs_count, wl_globs_count);
    for (size_t i=0;i<wl_files_count;i++) {
        log_msg("WF[%zu]: dev=%ju ino=%ju path=%s",
                i, (uintmax_t)wl_files[i].dev, (uintmax_t)wl_files[i].ino, wl_files[i].path);
    }
    for (size_t i=0;i<wl_dirs_count;i++) {
        log_msg("WD[%zu]: dir=%s", i, wl_dirs[i].dir);
    }
    for (size_t i=0;i<wl_globs_count;i++) {
        log_msg("WG[%zu]: dir=%s pattern=%s", i, wl_globs[i].dir, wl_globs[i].pattern);
    }
    return 0;
}

static bool allowed_by_files_fd(int fd) {
    if (!wl_files || wl_files_count == 0) return false;
    struct stat st;
    if (fstat(fd, &st) != 0) return false;
    size_t lo=0, hi=wl_files_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo)/2;
        int c = (st.st_dev < wl_files[mid].dev) ? -1 :
                (st.st_dev > wl_files[mid].dev) ?  1 :
                (st.st_ino < wl_files[mid].ino) ? -1 :
                (st.st_ino > wl_files[mid].ino) ?  1 : 0;
        if (c == 0) return true;
        if (c < 0) hi = mid; else lo = mid + 1;
    }
    return false;
}

static bool get_event_realpath(int fd, char *out, size_t outsz) {
    char linkpath[64];
    snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%d", fd);
    char tmp[PATH_MAX];
    ssize_t tlen = readlink(linkpath, tmp, sizeof(tmp)-1);
    if (tlen < 0) return false;
    tmp[tlen] = '\0';
    char resolved[PATH_MAX];
    if (realpath(tmp, resolved)) {
        strncpy(out, resolved, outsz);
        out[outsz-1]='\0';
        return true;
    } else {
        strncpy(out, tmp, outsz);
        out[outsz-1]='\0';
        return true;
    }
}

static bool allowed_by_dirs_fd(int fd) {
    if (!wl_dirs || wl_dirs_count == 0) return false;
    char path[PATH_MAX];
    if (!get_event_realpath(fd, path, sizeof(path))) return false;
    size_t L = strlen(path);
    for (size_t i=0;i<wl_dirs_count;i++) {
        const char *d = wl_dirs[i].dir; size_t dl = wl_dirs[i].len;
        if (L >= dl && strncmp(path, d, dl) == 0) return true;
    }
    return false;
}

static bool allowed_by_globs_fd(int fd) {
    if (!wl_globs || wl_globs_count == 0) return false;
    char path[PATH_MAX];
    if (!get_event_realpath(fd, path, sizeof(path))) return false;

    char *base = strrchr(path, '/');
    if (!base) return false;

    size_t dirlen = (size_t)(base - path); 

    for (size_t i=0;i<wl_globs_count;i++) {
        if (dirlen == wl_globs[i].dirlen && strncmp(path, wl_globs[i].dir, dirlen) == 0) {
            if (fnmatch(wl_globs[i].pattern, base, FNM_NOESCAPE) == 0) {
                return true;
            }
        }
    }
    return false;
}

typedef struct { pid_t pid; unsigned tokens; time_t expiry; } AllowEntry;
#define ALLOW_CACHE_SIZE 256
static AllowEntry allow_cache[ALLOW_CACHE_SIZE];

static unsigned hash_pid(pid_t p){ return ((unsigned)p * 2654435761u) % ALLOW_CACHE_SIZE; }
static void allow_pid_burst(pid_t p, unsigned tokens, unsigned ttl_seconds) {
    if (p <= 0 || tokens == 0) return;
    unsigned idx = hash_pid(p);
    allow_cache[idx].pid    = p;
    allow_cache[idx].tokens = tokens;
    allow_cache[idx].expiry = time(NULL) + (time_t)ttl_seconds;
}
static bool consume_pid_allow(pid_t p) {
    if (p <= 0) return false;
    unsigned idx = hash_pid(p);
    if (allow_cache[idx].pid != p) return false;
    time_t now = time(NULL);
    if (allow_cache[idx].expiry < now || allow_cache[idx].tokens == 0) return false;
    allow_cache[idx].tokens--;
    return true;
}

static int mark_all_mounts(int fd) {
    FILE *m = fopen("/proc/self/mounts", "r");
    if (!m) { log_msg("open /proc/self/mounts failed: %s", strerror(errno)); return -1; }
    char src[PATH_MAX], target[PATH_MAX], fstype[128], opts[512];
    int freq, passno;
    int marks=0, fails=0;

    while (fscanf(m, "%4095s %4095s %127s %511s %d %d\n", src, target, fstype, opts, &freq, &passno) == 6) {
        if (fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
                          FAN_OPEN_EXEC_PERM, AT_FDCWD, target) == -1) {
            fails++;
        } else {
            marks++;
        }
    }
    fclose(m);
    log_msg("fanotify marks: %d added, %d failed (pseudo-fs likely)", marks, fails);
    return marks > 0 ? 0 : -1;
}

static void handle_sighup(int sig) { (void)sig; want_reload = 1; }

static void say_killed_unauthorized(pid_t actor) {
    if (actor <= 0) return;
    const char *msg = "Running untrusted executables are not allowed.\n";
    char path[64]; int fd = -1;

    snprintf(path, sizeof(path), "/proc/%d/fd/2", actor);
    fd = open(path, O_WRONLY | O_NONBLOCK);
    if (fd < 0) {
        snprintf(path, sizeof(path), "/proc/%d/fd/1", actor);
        fd = open(path, O_WRONLY | O_NONBLOCK);
    }
    if (fd >= 0) { ssize_t w = write(fd, msg, strlen(msg)); (void)w; close(fd); }
}

int main(void) {
    log_msg("Starting (standalone)");

    struct sigaction sa = {0};
    sa.sa_handler = handle_sighup;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGHUP, &sa, NULL);

    if (load_whitelist() != 0) {
        log_msg("Continuing with empty whitelist (nothing will run)");
    }

    fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS,
                           O_RDONLY | O_LARGEFILE);
    if (fan_fd == -1) {
        log_msg("fanotify_init failed: %s", strerror(errno));
        return 1;
    }
    if (mark_all_mounts(fan_fd) != 0) {
        log_msg("Could not mark any mounts; exiting");
        return 1;
    }

    for (;;) {
        if (want_reload) { want_reload = 0; load_whitelist(); }

        char buf[8192] __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));
        ssize_t len = read(fan_fd, buf, sizeof(buf));
        if (len == -1) {
            if (errno == EAGAIN || errno == EINTR) continue;
            log_msg("fanotify read error: %s", strerror(errno));
            break;
        }

        struct fanotify_event_metadata *meta = (struct fanotify_event_metadata *)buf;
        while (FAN_EVENT_OK(meta, len)) {
            if (meta->vers != FANOTIFY_METADATA_VERSION) {
                log_msg("fanotify metadata version mismatch");
                return 2;
            }

            if (meta->fd >= 0 && (meta->mask & FAN_OPEN_EXEC_PERM)) {
                bool by_file  = allowed_by_files_fd(meta->fd);
                bool by_dir   = (!by_file) && allowed_by_dirs_fd(meta->fd);
                bool by_glob  = (!by_file && !by_dir) && allowed_by_globs_fd(meta->fd);
                bool by_burst = (!by_file && !by_dir && !by_glob) && consume_pid_allow(meta->pid);
                bool allow    = by_file || by_dir || by_glob || by_burst;

                struct fanotify_response resp = { .fd = meta->fd,
                                                  .response = allow ? FAN_ALLOW : FAN_DENY };
                if (write(fan_fd, &resp, sizeof(resp)) != sizeof(resp)) {
                    log_msg("Failed writing fanotify response: %s", strerror(errno));
                }

                if (allow) {
                    if (by_file || by_dir || by_glob) {
                        allow_pid_burst(meta->pid, 1, 2);
                    }
                } else {
                    pid_t actor = meta->pid;
                    if (actor > 0) say_killed_unauthorized(actor);
                    if (actor > 0) {
                        if (kill(actor, SIGKILL) == -1) {
                            log_msg("Failed to SIGKILL pid %d: %s", actor, strerror(errno));
                        } else {
                            log_msg("Denied and killed pid %d (non-whitelisted exec)", actor);
                        }
                    } else {
                        log_msg("Denied non-whitelisted exec (unknown pid)");
                    }
                }
                close(meta->fd);
            }

            meta = FAN_EVENT_NEXT(meta, len);
        }
    }

    if (fan_fd != -1) close(fan_fd);
    free_whitelist();
    log_msg("Exiting");
    return 0;
}
