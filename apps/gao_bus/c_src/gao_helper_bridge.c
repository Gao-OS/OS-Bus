#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

/* Package-time binding only. An unconfigured build cannot fork a helper. */
#ifndef GAO_HELPER_PATH
#define GAO_HELPER_PATH ""
#endif

/* Capture/packaging can inspect the exact immutable binding without execution. */
static const char gao_helper_binding[]
    __attribute__((used, retain, section(".gao_helper_binding"))) = GAO_HELPER_PATH;

enum kind { NOT_STARTED = 1, EXEC_FAILED, EXITED, SIGNALED, OBSERVATION_FAILED };
enum stage {
    NONE = 0, ARGUMENT, BINDING, HARDENING, STDIO, CLOSE_FDS, ERROR_PIPE,
    FORK, SIGNALS, EXEC, WAIT, ERROR_READ
};

static void uint32_bytes(unsigned char *out, uint32_t value) {
    out[0] = (unsigned char)(value >> 24);
    out[1] = (unsigned char)(value >> 16);
    out[2] = (unsigned char)(value >> 8);
    out[3] = (unsigned char)value;
}

static uint32_t bytes_uint32(const unsigned char *in) {
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) | in[3];
}

static int write_bytes(int fd, const unsigned char *bytes, size_t size) {
    while (size) {
        ssize_t count = write(fd, bytes, size);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        bytes += count;
        size -= (size_t)count;
    }
    return 0;
}

static int report(enum kind kind, enum stage stage, uint32_t value) {
    unsigned char record[16] = {'G', 'H', 'B', 1, (unsigned char)kind,
                               (unsigned char)stage, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint32_bytes(record + 8, value);
    return write_bytes(STDOUT_FILENO, record, sizeof(record)) == 0 ? 0 : 1;
}

static int name_start(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c == '-';
}

static int valid_name(const char *name) {
    size_t length = strnlen(name, 256);
    if (!length || length > 255 || !strcmp(name, "org.freedesktop.DBus")) return 0;
    int start = 1, dots = 0;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)name[i];
        if (start) {
            if (!name_start(c)) return 0;
            start = 0;
        } else if (c == '.') {
            start = 1; dots++;
        } else if (!name_start(c) && !(c >= '0' && c <= '9')) {
            return 0;
        }
    }
    return dots && !start;
}

static void child_error(int fd, enum stage stage, int error) {
    unsigned char record[12] = {'G', 'C', 'E', 1, (unsigned char)stage, 0, 0, 0,
                               0, 0, 0, 0};
    uint32_bytes(record + 8, (uint32_t)error);
    (void)write_bytes(fd, record, sizeof(record));
    _exit(126);
}

static int signal_defaults(void) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask)) return -1;
    for (int number = 1; number < NSIG; number++) {
        if (number == SIGKILL || number == SIGSTOP) continue;
        /* glibc's internal reserved signal numbers reject sigaction. */
        if (sigaction(number, &action, NULL) && errno != EINVAL) return -1;
    }
    sigset_t mask;
    if (sigemptyset(&mask) || sigprocmask(SIG_SETMASK, &mask, NULL)) return -1;
    return 0;
}

int main(int argc, char **argv) {
    /* Do not die on a broken observer pipe before the direct child is reaped. */
    struct sigaction ignore;
    memset(&ignore, 0, sizeof(ignore));
    ignore.sa_handler = SIG_IGN;
    if (sigemptyset(&ignore.sa_mask) || sigaction(SIGPIPE, &ignore, NULL)) return 1;

    if (argc != 2 || !valid_name(argv[1])) return report(NOT_STARTED, ARGUMENT, EINVAL);
    if (gao_helper_binding[0] != '/') return report(NOT_STARTED, BINDING, ENOENT);

    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core) || prctl(PR_SET_DUMPABLE, 0, 0, 0, 0))
        return report(NOT_STARTED, HARDENING, (uint32_t)errno);

    int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd < 0 || dup2(null_fd, STDIN_FILENO) < 0 || dup2(null_fd, STDERR_FILENO) < 0 ||
        fcntl(STDIN_FILENO, F_SETFD, 0) < 0 || fcntl(STDERR_FILENO, F_SETFD, 0) < 0)
        return report(NOT_STARTED, STDIO, (uint32_t)errno);
    /* Linux close_range is the complete FD-table boundary; no guessed ceiling. */
    if (close_range(3, UINT_MAX, 0)) return report(NOT_STARTED, CLOSE_FDS, (uint32_t)errno);

    /* Ignored SIGCHLD or an inherited blocked mask must not defeat waitpid. */
    struct sigaction child_signal;
    memset(&child_signal, 0, sizeof(child_signal));
    child_signal.sa_handler = SIG_DFL;
    sigset_t mask;
    if (sigemptyset(&child_signal.sa_mask) || sigaction(SIGCHLD, &child_signal, NULL) ||
        sigemptyset(&mask) || sigprocmask(SIG_SETMASK, &mask, NULL))
        return report(NOT_STARTED, SIGNALS, (uint32_t)errno);

    int errors[2];
    if (pipe2(errors, O_CLOEXEC)) return report(NOT_STARTED, ERROR_PIPE, (uint32_t)errno);
    pid_t child = fork();
    if (child < 0) return report(NOT_STARTED, FORK, (uint32_t)errno);
    if (child == 0) {
        /* pipe2 yields read=3/write=4 after complete parent closure. */
        if (dup3(errors[1], 3, O_CLOEXEC) < 0) child_error(errors[1], CLOSE_FDS, errno);
        if (dup2(STDIN_FILENO, STDOUT_FILENO) < 0) child_error(3, STDIO, errno);
        if (close_range(4, UINT_MAX, 0)) child_error(3, CLOSE_FDS, errno);
        if (signal_defaults()) child_error(3, SIGNALS, errno);
        char *const arguments[] = {(char *)gao_helper_binding, argv[1], NULL};
        char *const environment[] = {NULL};
        execve(gao_helper_binding, arguments, environment);
        child_error(3, EXEC, errno);
    }
    close(errors[1]);

    int status;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited != child) return report(OBSERVATION_FAILED, WAIT, (uint32_t)errno);

    /* 12 private bytes plus one overflow detector, only after direct-child reap. */
    unsigned char error[13];
    size_t length = 0;
    while (length < sizeof(error)) {
        ssize_t count = read(errors[0], error + length, sizeof(error) - length);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) return report(OBSERVATION_FAILED, ERROR_READ, (uint32_t)errno);
        if (!count) break;
        length += (size_t)count;
    }
    close(errors[0]);
    if (length) {
        if (length != 12 || memcmp(error, "GCE\1", 4) || error[5] || error[6] || error[7] ||
            error[4] < STDIO || error[4] > EXEC || !bytes_uint32(error + 8) ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 126)
            return report(OBSERVATION_FAILED, ERROR_READ, EPROTO);
        return report(EXEC_FAILED, (enum stage)error[4], bytes_uint32(error + 8));
    }
    if (WIFEXITED(status)) return report(EXITED, NONE, (uint32_t)WEXITSTATUS(status));
    if (WIFSIGNALED(status)) return report(SIGNALED, NONE, (uint32_t)WTERMSIG(status));
    return report(OBSERVATION_FAILED, WAIT, EPROTO);
}
