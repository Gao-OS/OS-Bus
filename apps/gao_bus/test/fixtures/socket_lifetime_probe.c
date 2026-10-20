/* Test-only NIF: syscall barriers and forced descriptor reuse never ship. */
#define _GNU_SOURCE
#include <erl_nif.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

static ErlNifMutex *probe_mutex;
static ErlNifCond *probe_condition;
static ErlNifPid probe_observer;
static int probe_phase, probe_entered, probe_released, probe_finished;

static void barrier(int phase) {
    enif_mutex_lock(probe_mutex);
    if (probe_phase == phase) {
        probe_entered = 1;
        ErlNifEnv *message_env = enif_alloc_env();
        ERL_NIF_TERM message = enif_make_tuple2(message_env,
            enif_make_atom(message_env, "native_barrier"), enif_make_int(message_env, phase));
        enif_send(NULL, &probe_observer, message_env, message);
        enif_free_env(message_env);
        while (!probe_released) enif_cond_wait(probe_condition, probe_mutex);
    }
    enif_mutex_unlock(probe_mutex);
}
static void finished(void) {
    enif_mutex_lock(probe_mutex);
    probe_finished = 1;
    ErlNifEnv *message_env = enif_alloc_env();
    ERL_NIF_TERM message = enif_make_tuple2(message_env,
        enif_make_atom(message_env, "native_complete"), enif_make_int(message_env, probe_phase));
    enif_send(NULL, &probe_observer, message_env, message);
    enif_free_env(message_env);
    enif_mutex_unlock(probe_mutex);
}
static ssize_t probed_recvmsg(int fd, struct msghdr *message, int flags) {
    barrier(1);
    ssize_t result = recvmsg(fd, message, flags);
    barrier(3);
    return result;
}
static ssize_t probed_sendmsg(int fd, const struct msghdr *message, int flags) {
    barrier(2);
    ssize_t result = sendmsg(fd, message, flags);
    return result;
}
#define recvmsg probed_recvmsg
#define sendmsg probed_sendmsg
#pragma push_macro("ERL_NIF_INIT")
#undef ERL_NIF_INIT
#define ERL_NIF_INIT(...)
#include "../../c_src/gao_unix.c"
#pragma pop_macro("ERL_NIF_INIT")
#undef recvmsg
#undef sendmsg

/* Completion covers parsing/temporary-rights cleanup, not only the syscall. */
static ERL_NIF_TERM complete_recv(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    ERL_NIF_TERM result = receive_rights(env, argc, argv);
    finished();
    return result;
}
static ERL_NIF_TERM complete_send(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    ERL_NIF_TERM result = send_rights(env, argc, argv);
    finished();
    return result;
}
static ERL_NIF_TERM entered_close(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifEnv *message_env = enif_alloc_env();
    enif_send(NULL, &probe_observer, message_env,
        enif_make_atom(message_env, "native_close_entered"));
    enif_free_env(message_env);
    return close_resource(env, argc, argv);
}
static ERL_NIF_TERM resource_fd(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    owned_fd *resource;
    if (!enif_get_resource(env, argv[0], fd_type, (void **)&resource))
        return enif_make_badarg(env);
    enif_mutex_lock(resource->lock);
    int fd = resource->fd;
    enif_mutex_unlock(resource->lock);
    return enif_make_int(env, fd);
}

static ERL_NIF_TERM arm(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    int phase;
    ErlNifPid observer;
    if (!enif_get_int(env, argv[0], &phase) || phase < 1 || phase > 3 ||
        !enif_get_local_pid(env, argv[1], &observer)) return enif_make_badarg(env);
    enif_mutex_lock(probe_mutex);
    probe_phase = phase; probe_entered = 0; probe_released = 0; probe_finished = 0;
    probe_observer = observer;
    enif_mutex_unlock(probe_mutex);
    return atom(env, "ok");
}
static ERL_NIF_TERM release_barrier(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    enif_mutex_lock(probe_mutex);
    probe_released = 1;
    enif_cond_broadcast(probe_condition);
    enif_mutex_unlock(probe_mutex);
    return atom(env, "ok");
}
static ERL_NIF_TERM status(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    enif_mutex_lock(probe_mutex);
    int done = probe_finished;
    enif_mutex_unlock(probe_mutex);
    return atom(env, done ? "done" : "waiting");
}
static ERL_NIF_TERM reuse(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    int fd, pair[2];
    if (!enif_get_int(env, argv[0], &fd) || fd < 0) return enif_make_badarg(env);
    if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) return error(env, "busy");
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, pair))
        return system_error(env, errno);
    if (pair[0] != fd) {
        if (pair[1] == fd) { int swap = pair[0]; pair[0] = pair[1]; pair[1] = swap; }
        else {
            if (dup3(pair[0], fd, O_CLOEXEC) == -1) {
                int failure = errno; close(pair[0]); close(pair[1]);
                return system_error(env, failure);
            }
            close(pair[0]);
        }
    }
    return enif_make_tuple2(env, atom(env, "ok"), enif_make_int(env, pair[1]));
}
static ERL_NIF_TERM raw_write(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    int fd; ErlNifBinary bytes;
    if (!enif_get_int(env, argv[0], &fd) || !enif_inspect_binary(env, argv[1], &bytes))
        return enif_make_badarg(env);
    ssize_t written = send(fd, bytes.data, bytes.size, MSG_DONTWAIT | MSG_NOSIGNAL);
    return written < 0 ? system_error(env, errno) : atom(env, "ok");
}
static ERL_NIF_TERM raw_read(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    int fd;
    if (!enif_get_int(env, argv[0], &fd)) return enif_make_badarg(env);
    unsigned char bytes[1024], control[CMSG_SPACE(MAX_RIGHTS * sizeof(int))];
    struct iovec iov = {.iov_base = bytes, .iov_len = sizeof(bytes)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    ssize_t received = recvmsg(fd, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    if (received < 0) return system_error(env, errno);
    unsigned rights = 0;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message); cmsg; cmsg = CMSG_NXTHDR(&message, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            unsigned count = (unsigned)((cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int));
            rights += count;
            close_many((int *)CMSG_DATA(cmsg), count);
        }
    }
    ERL_NIF_TERM data;
    unsigned char *destination = enif_make_new_binary(env, (size_t)received, &data);
    memcpy(destination, bytes, (size_t)received);
    return enif_make_tuple3(env, atom(env, "ok"), data, enif_make_uint(env, rights));
}
static ERL_NIF_TERM raw_close(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    int first, second;
    if (!enif_get_int(env, argv[0], &first) || !enif_get_int(env, argv[1], &second))
        return enif_make_badarg(env);
    close(first); close(second);
    return atom(env, "ok");
}
static ERL_NIF_TERM test_resource(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    int pipe_fds[2];
    if (pipe2(pipe_fds, O_CLOEXEC)) return system_error(env, errno);
    close(pipe_fds[1]);
    owned_fd *resource = enif_alloc_resource(fd_type, sizeof(*resource));
    resource->fd = pipe_fds[0]; resource->lock = enif_mutex_create("test_fd");
    ERL_NIF_TERM handle = enif_make_resource(env, resource);
    enif_release_resource(resource);
    return handle;
}
static int probe_load(ErlNifEnv *env, void **priv, ERL_NIF_TERM info) {
    (void)functions;
    if (load(env, priv, info)) return -1;
    probe_mutex = enif_mutex_create("test_barrier");
    probe_condition = enif_cond_create("test_barrier");
    return probe_mutex && probe_condition ? 0 : -1;
}
static ErlNifFunc probe_functions[] = {
#ifdef GAO_UNIX_SOCKET_CAPTURE
    {"capture", 1, capture_socket, 0},
#endif
    {"recv", 3, complete_recv, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"send", 3, complete_send, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"close", 1, entered_close, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"arm", 2, arm, 0}, {"release", 0, release_barrier, 0}, {"status", 0, status, 0},
    {"reuse", 1, reuse, 0}, {"raw_write", 2, raw_write, 0}, {"raw_read", 1, raw_read, 0},
    {"raw_close", 2, raw_close, 0}, {"resource", 0, test_resource, 0},
    {"resource_fd", 1, resource_fd, 0}
};
ERL_NIF_INIT(Elixir.GaoBus.Unix.NativeProbe, probe_functions, probe_load, NULL, NULL, NULL)
