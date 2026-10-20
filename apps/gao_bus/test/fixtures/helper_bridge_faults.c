#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Link-time fault injection belongs only to the private fixture build. */
#if defined(FAULT_FORK)
pid_t __wrap_fork(void) { errno = EAGAIN; return -1; }
#elif defined(FAULT_WAIT)
pid_t __real_waitpid(pid_t, int *, int);
pid_t __wrap_waitpid(pid_t pid, int *status, int options) {
    pid_t result = __real_waitpid(pid, status, options);
    if (result == pid) { errno = ECHILD; return -1; }
    return result;
}
#elif defined(FAULT_EINTR)
pid_t __real_waitpid(pid_t, int *, int);
pid_t __wrap_waitpid(pid_t pid, int *status, int options) {
    static int once;
    if (!once++) { errno = EINTR; return -1; }
    return __real_waitpid(pid, status, options);
}
#elif defined(FAULT_PIPE)
int __wrap_pipe2(int pipefd[2], int flags) {
    (void)pipefd; (void)flags; errno = EMFILE; return -1;
}
#elif defined(FAULT_HARDENING)
int __wrap_prctl(int option, ...) { (void)option; errno = EPERM; return -1; }
#elif defined(FAULT_MOVE)
int __wrap_dup3(int oldfd, int newfd, int flags) {
    (void)oldfd; (void)newfd; (void)flags; errno = EBUSY; return -1;
}
#elif defined(FAULT_READ)
ssize_t __wrap_read(int fd, void *buffer, size_t count) {
    (void)fd; (void)buffer; (void)count; errno = EIO; return -1;
}
#elif defined(FAULT_CLOSE) || defined(FAULT_CHILD_CLOSE)
int __real_close_range(unsigned int, unsigned int, int);
static pid_t initial_pid;
__attribute__((constructor)) static void initial(void) { initial_pid = getpid(); }
int __wrap_close_range(unsigned int first, unsigned int last, int flags) {
#if defined(FAULT_CHILD_CLOSE)
    if (getpid() == initial_pid) return __real_close_range(first, last, flags);
#else
    (void)initial_pid;
#endif
    (void)first; (void)last; (void)flags; errno = ENOSYS; return -1;
}
#endif
