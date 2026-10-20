#define _GNU_SOURCE
#include <erl_nif.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <poll.h>
#include <dirent.h>
#include <stddef.h>
#include <sys/stat.h>

/* Linux SCM_MAX_FD. Receive capacity never exceeds the caller's FD credit. */
#define GAO_UNIX_SOCKET_CAPTURE 1
#define MAX_RIGHTS 253
#define MAX_BYTES 65536

typedef struct {
    int fd;
    ErlNifMutex *lock;
} owned_fd;

static ErlNifResourceType *fd_type;
static ERL_NIF_TERM atom(ErlNifEnv *env, const char *name) {
    return enif_make_atom(env, name);
}
static ERL_NIF_TERM error(ErlNifEnv *env, const char *name) {
    return enif_make_tuple2(env, atom(env, "error"), atom(env, name));
}
static ERL_NIF_TERM system_error(ErlNifEnv *env, int value) {
    const char *name;
    switch (value) {
    case EAGAIN: name = "eagain"; break;
    case EINTR: name = "eintr"; break;
    case EBADF: name = "ebadf"; break;
    case EPIPE: name = "epipe"; break;
    case ECONNRESET: name = "econnreset"; break;
    case ENOTSOCK: name = "enotsock"; break;
    case ENOBUFS: name = "enobufs"; break;
    case ENOMEM: name = "enomem"; break;
    case EMFILE: name = "emfile"; break;
    case ENFILE: name = "enfile"; break;
    default:
        return enif_make_tuple2(env, atom(env, "error"),
            enif_make_tuple2(env, atom(env, "errno"), enif_make_int(env, value)));
    }
    return error(env, name);
}
/* Linux releases ownership on close, including EINTR: never retry a reused fd. */
static int close_fd(int fd) { return close(fd) == 0 ? 0 : errno; }
static void destructor(ErlNifEnv *env, void *object) {
    (void)env;
    owned_fd *resource = object;
    if (resource->fd >= 0) {
        int failure = close_fd(resource->fd);
        if (failure) enif_fprintf(stderr, "gao_unix: resource close failed (%d)\n", failure);
    }
    if (resource->lock) enif_mutex_destroy(resource->lock);
}
static int close_many(int *fds, unsigned count) {
    int first_error = 0;
    for (unsigned i = 0; i < count; i++) {
        int failure = close_fd(fds[i]);
        if (failure && !first_error) first_error = failure;
    }
    return first_error;
}
/* Bounded ordinary-scheduler startup handoff. Caller owns and retains the
   public OTP duplicate throughout this call; trusted startup does not close
   or transfer either descriptor concurrently. The duplicate's owner cannot
   finish exiting while the call runs. Original fd3 has no OTP/resource owner:
   close it exactly once after matching socket identity and proving CLOEXEC on
   the duplicate. No shutdown, O_NONBLOCK changes or new ownership resource. */
static ERL_NIF_TERM inherited_listener_handoff(ErlNifEnv *env, int argc,
                                              const ERL_NIF_TERM argv[]) {
    (void)argc;
    int fd;
    if (!enif_get_int(env, argv[0], &fd) || fd < 0 || fd == 3)
        return error(env, "invalid_inherited_fd");
    struct stat original, duplicate;
    if (fstat(3, &original) < 0 || fstat(fd, &duplicate) < 0)
        return system_error(env, errno);
    if (!S_ISSOCK(original.st_mode) || !S_ISSOCK(duplicate.st_mode) ||
        original.st_dev != duplicate.st_dev || original.st_ino != duplicate.st_ino)
        return error(env, "invalid_inherited_identity");
    const int descriptors[] = {3, fd};
    for (unsigned i = 0; i < 2; i++) {
        struct sockaddr_storage address;
        socklen_t length = sizeof(address);
        if (getsockname(descriptors[i], (struct sockaddr *)&address, &length) < 0)
            return system_error(env, errno);
        if (address.ss_family != AF_UNIX) return error(env, "invalid_inherited_domain");
        int type, listening;
        length = sizeof(type);
        if (getsockopt(descriptors[i], SOL_SOCKET, SO_TYPE, &type, &length) < 0)
            return system_error(env, errno);
        if (type != SOCK_STREAM) return error(env, "invalid_inherited_type");
        length = sizeof(listening);
        if (getsockopt(descriptors[i], SOL_SOCKET, SO_ACCEPTCONN, &listening, &length) < 0)
            return system_error(env, errno);
        if (!listening) return error(env, "inherited_socket_not_listening");
    }
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0) return system_error(env, errno);
    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) return system_error(env, errno);
    flags = fcntl(fd, F_GETFD);
    if (flags < 0) return system_error(env, errno);
    if (!(flags & FD_CLOEXEC)) return error(env, "inherited_cloexec_not_set");
    int failure = close_fd(3);
    return failure ? system_error(env, failure) : atom(env, "ok");
}
/* This bounded bootstrap runs on the ordinary scheduler: the owning caller
   cannot finish exiting and close/reuse the borrowed integer during duplication. */
static ERL_NIF_TERM capture_socket(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    int original;
    if (!enif_get_int(env, argv[0], &original) || original < 0) return enif_make_badarg(env);
    int fd = fcntl(original, F_DUPFD_CLOEXEC, 0);
    if (fd < 0) return system_error(env, errno);
    owned_fd *resource = enif_alloc_resource(fd_type, sizeof(*resource));
    if (!resource) {
        int failure = close_fd(fd);
        return failure ? system_error(env, failure) : error(env, "enomem");
    }
    resource->fd = fd;
    resource->lock = enif_mutex_create("gao_bus_socket");
    if (!resource->lock) {
        int failure = close_fd(fd);
        resource->fd = -1;
        enif_release_resource(resource);
        return failure ? system_error(env, failure) : error(env, "enomem");
    }
    ERL_NIF_TERM handle = enif_make_resource(env, resource);
    enif_release_resource(resource);
    return enif_make_tuple2(env, atom(env, "ok"), handle);
}
static ERL_NIF_TERM receive_rights(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    owned_fd *socket_resource;
    unsigned max_bytes, max_fds;
    if (!enif_get_resource(env, argv[0], fd_type, (void **)&socket_resource) ||
        !enif_get_uint(env, argv[1], &max_bytes) || max_bytes == 0 || max_bytes > MAX_BYTES ||
        !enif_get_uint(env, argv[2], &max_fds) || max_fds > MAX_RIGHTS)
        return enif_make_badarg(env);

    ErlNifBinary bytes;
    if (!enif_alloc_binary(max_bytes, &bytes)) return error(env, "enomem");
    union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(MAX_RIGHTS * sizeof(int))]; } control;
    struct iovec iov = { .iov_base = bytes.data, .iov_len = max_bytes };
    struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1,
        /* CMSG_SPACE padding can admit one additional int. CMSG_LEN gives the
           exact rights ceiling; credentials are unsupported, not extra headroom.
           The kernel closes rights omitted by MSG_CTRUNC before returning. */
        .msg_control = max_fds ? control.bytes : NULL,
        .msg_controllen = max_fds ? CMSG_LEN(max_fds * sizeof(int)) : 0 };
    enif_mutex_lock(socket_resource->lock);
    int fd = socket_resource->fd;
    if (fd < 0) {
        enif_mutex_unlock(socket_resource->lock);
        enif_release_binary(&bytes);
        return error(env, "closed");
    }
    ssize_t received = recvmsg(fd, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    int receive_errno = errno;
    enif_mutex_unlock(socket_resource->lock);
    if (received < 0) {
        int failure = receive_errno;
        enif_release_binary(&bytes);
        return system_error(env, failure);
    }
    int rights[MAX_RIGHTS];
    unsigned count = 0;
    int unsupported_control = 0;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message); cmsg; cmsg = CMSG_NXTHDR(&message, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            size_t size = cmsg->cmsg_len - CMSG_LEN(0);
            unsigned entries = (unsigned)(size / sizeof(int));
            if (size % sizeof(int) || entries > MAX_RIGHTS - count) {
                unsupported_control = 1;
                /* The kernel bounds cmsg_len to this buffer; this branch is defensive. */
                entries = MAX_RIGHTS - count;
            }
            memcpy(rights + count, CMSG_DATA(cmsg), entries * sizeof(int));
            count += entries;
        } else {
            unsupported_control = 1;
        }
    }
    const char *failure = NULL;
    if (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) failure = "control_truncated";
    else if (unsupported_control) failure = "unsupported_control";
    else if (count > max_fds) failure = "too_many_fds";
    else if (received == 0) failure = "closed";
    if (failure) {
        int cleanup_failure = close_many(rights, count);
        enif_release_binary(&bytes);
        return cleanup_failure ? system_error(env, cleanup_failure) : error(env, failure);
    }
    if (!enif_realloc_binary(&bytes, (size_t)received)) {
        int cleanup_failure = close_many(rights, count);
        enif_release_binary(&bytes);
        return cleanup_failure ? system_error(env, cleanup_failure) : error(env, "enomem");
    }
    /* Keep native references until all allocations succeed. No partially built
       term may postpone closing rights until an unrelated Erlang GC. */
    owned_fd *resources[MAX_RIGHTS];
    unsigned allocated = 0;
    for (unsigned i = 0; i < count; i++) {
        owned_fd *resource = enif_alloc_resource(fd_type, sizeof(*resource));
        if (resource) {
            resource->fd = -1;
            resource->lock = enif_mutex_create("gao_bus_fd");
            resources[allocated++] = resource;
        }
        if (!resource || !resource->lock) {
            int cleanup_failure = close_many(rights, count);
            for (unsigned j = 0; j < allocated; j++) enif_release_resource(resources[j]);
            enif_release_binary(&bytes);
            return cleanup_failure ? system_error(env, cleanup_failure) : error(env, "enomem");
        }
    }
    ERL_NIF_TERM list = enif_make_list(env, 0);
    for (unsigned i = count; i > 0; i--) {
        owned_fd *resource = resources[i - 1];
        resource->fd = rights[i - 1];
        list = enif_make_list_cell(env, enif_make_resource(env, resource), list);
        enif_release_resource(resource);
    }
    return enif_make_tuple3(env, atom(env, "ok"), enif_make_binary(env, &bytes), list);
}
static ERL_NIF_TERM send_rights(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    owned_fd *socket_resource;
    ErlNifBinary bytes;
    unsigned count;
    if (!enif_get_resource(env, argv[0], fd_type, (void **)&socket_resource) ||
        !enif_inspect_binary(env, argv[1], &bytes) ||
        bytes.size == 0 || bytes.size > MAX_BYTES ||
        !enif_get_list_length(env, argv[2], &count) || count > MAX_RIGHTS)
        return enif_make_badarg(env);
    int rights[MAX_RIGHTS];
    unsigned copied = 0;
    ERL_NIF_TERM rest = argv[2], head;
    while (enif_get_list_cell(env, rest, &head, &rest)) {
        owned_fd *resource;
        if (!enif_get_resource(env, head, fd_type, (void **)&resource)) {
            int cleanup_failure = close_many(rights, copied);
            return cleanup_failure ? system_error(env, cleanup_failure) : enif_make_badarg(env);
        }
        enif_mutex_lock(resource->lock);
        int owned = resource->fd;
        int duplicate = owned < 0 ? -1 : fcntl(owned, F_DUPFD_CLOEXEC, 0);
        int saved_errno = errno;
        enif_mutex_unlock(resource->lock);
        if (duplicate < 0) {
            int cleanup_failure = close_many(rights, copied);
            if (cleanup_failure) return system_error(env, cleanup_failure);
            return owned < 0 ? error(env, "closed") : system_error(env, saved_errno);
        }
        rights[copied++] = duplicate;
    }
    struct iovec iov = { .iov_base = bytes.data, .iov_len = bytes.size };
    union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(MAX_RIGHTS * sizeof(int))]; } control;
    struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1 };
    if (count) {
        message.msg_control = control.bytes;
        message.msg_controllen = CMSG_SPACE(count * sizeof(int));
        memset(control.bytes, 0, message.msg_controllen);
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(count * sizeof(int));
        memcpy(CMSG_DATA(cmsg), rights, count * sizeof(int));
    }
    enif_mutex_lock(socket_resource->lock);
    int fd = socket_resource->fd;
    if (fd < 0) {
        enif_mutex_unlock(socket_resource->lock);
        int cleanup_failure = close_many(rights, count);
        return cleanup_failure ? system_error(env, cleanup_failure) : error(env, "closed");
    }
    ssize_t sent = sendmsg(fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
    int saved_errno = errno;
    enif_mutex_unlock(socket_resource->lock);
    int cleanup_failure = close_many(rights, count);
    if (cleanup_failure) return system_error(env, cleanup_failure);
    if (sent < 0) return system_error(env, saved_errno);
    return enif_make_tuple2(env, atom(env, "ok"), enif_make_uint64(env, (ErlNifUInt64)sent));
}
static ERL_NIF_TERM close_resource(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    owned_fd *resource;
    if (!enif_get_resource(env, argv[0], fd_type, (void **)&resource)) return enif_make_badarg(env);
    enif_mutex_lock(resource->lock);
    int fd = resource->fd;
    resource->fd = -1;
    int failure = fd < 0 ? 0 : close_fd(fd);
    enif_mutex_unlock(resource->lock);
    return failure ? system_error(env, failure) : atom(env, "ok");
}
static ERL_NIF_TERM duplicate_resources(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    unsigned count;
    if (!enif_get_list_length(env, argv[0], &count) || count > MAX_RIGHTS)
        return enif_make_badarg(env);
    owned_fd *copies[MAX_RIGHTS];
    unsigned allocated = 0;
    ERL_NIF_TERM rest = argv[0], head, failure;
    while (enif_get_list_cell(env, rest, &head, &rest)) {
        owned_fd *source;
        if (!enif_get_resource(env, head, fd_type, (void **)&source)) {
            failure = enif_make_badarg(env);
            goto rollback;
        }
        enif_mutex_lock(source->lock);
        int original = source->fd;
        int fd = original < 0 ? -1 : fcntl(original, F_DUPFD_CLOEXEC, 0);
        int saved_errno = errno;
        enif_mutex_unlock(source->lock);
        if (fd < 0) {
            failure = original < 0 ? error(env, "closed") : system_error(env, saved_errno);
            goto rollback;
        }
        owned_fd *copy = enif_alloc_resource(fd_type, sizeof(*copy));
        if (!copy) {
            int cleanup_failure = close_fd(fd);
            failure = cleanup_failure ? system_error(env, cleanup_failure) : error(env, "enomem");
            goto rollback;
        }
        copy->fd = fd;
        copy->lock = enif_mutex_create("gao_bus_fd");
        copies[allocated++] = copy;
        if (!copy->lock) {
            failure = error(env, "enomem");
            goto rollback;
        }
    }
    ERL_NIF_TERM list = enif_make_list(env, 0);
    for (unsigned i = count; i > 0; i--) {
        list = enif_make_list_cell(env, enif_make_resource(env, copies[i - 1]), list);
        enif_release_resource(copies[i - 1]);
    }
    return enif_make_tuple2(env, atom(env, "ok"), list);
rollback:
    /* No Erlang resource terms exist until the entire transaction succeeds. */
    /* Close synchronously: rollback must not depend on destructor scheduling. */
    int cleanup_failure = 0;
    for (unsigned i = 0; i < allocated; i++) {
        int close_failure = close_fd(copies[i]->fd);
        copies[i]->fd = -1;
        if (!cleanup_failure) cleanup_failure = close_failure;
        enif_release_resource(copies[i]);
    }
    return cleanup_failure ? system_error(env, cleanup_failure) : failure;
}
static ERL_NIF_TERM writable(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    owned_fd *socket_resource;
    if (!enif_get_resource(env, argv[0], fd_type, (void **)&socket_resource))
        return enif_make_badarg(env);
    enif_mutex_lock(socket_resource->lock);
    int fd = socket_resource->fd;
    if (fd < 0) {
        enif_mutex_unlock(socket_resource->lock);
        return error(env, "closed");
    }
    struct pollfd descriptor = { .fd = fd, .events = POLLOUT };
    int ready = poll(&descriptor, 1, 0);
    int saved_errno = errno;
    enif_mutex_unlock(socket_resource->lock);
    if (ready < 0) return system_error(env, saved_errno);
    if (descriptor.revents & POLLNVAL) return error(env, "ebadf");
    if (descriptor.revents & POLLHUP) return error(env, "closed");
    if (descriptor.revents & POLLERR) return error(env, "epipe");
    return enif_make_tuple2(env, atom(env, "ok"),
        atom(env, descriptor.revents & POLLOUT ? "true" : "false"));
}
static ERL_NIF_TERM resource_info(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    owned_fd *resource;
    if (!enif_get_resource(env, argv[0], fd_type, (void **)&resource)) return enif_make_badarg(env);
    enif_mutex_lock(resource->lock);
    int fd = resource->fd;
    int flags = fd < 0 ? -1 : fcntl(fd, F_GETFD);
    int saved_errno = errno;
    enif_mutex_unlock(resource->lock);
    if (fd < 0) return error(env, "closed");
    if (flags < 0) return system_error(env, saved_errno);
    ERL_NIF_TERM map = enif_make_new_map(env);
    enif_make_map_put(env, map, atom(env, "cloexec"), atom(env, flags & FD_CLOEXEC ? "true" : "false"), &map);
    return enif_make_tuple2(env, atom(env, "ok"), map);
}
static ERL_NIF_TERM identity(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    ERL_NIF_TERM map = enif_make_new_map(env);
    enif_make_map_put(env, map, atom(env, "pid"), enif_make_int(env, getpid()), &map);
    enif_make_map_put(env, map, atom(env, "uid"), enif_make_uint(env, geteuid()), &map);
    enif_make_map_put(env, map, atom(env, "gid"), enif_make_uint(env, getegid()), &map);
    enif_make_map_put(env, map, atom(env, "real_uid"), enif_make_uint(env, getuid()), &map);
    enif_make_map_put(env, map, atom(env, "real_gid"), enif_make_uint(env, getgid()), &map);
    return map;
}

#define MAX_DIRECTORY_ENTRIES 1024
#define MAX_DIRECTORY_NAME_BYTES 262144
#define MAX_DIRECTORY_NAME 255
#define MAX_DIRECTORY_PATH 4096
#define DIRECTORY_SCRATCH_BYTES 32768

typedef struct {
    unsigned char scratch[DIRECTORY_SCRATCH_BYTES];
    ErlNifBinary names[MAX_DIRECTORY_ENTRIES];
    unsigned allocated;
} directory_read;

static int same_directory(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
        left->st_mode == right->st_mode && left->st_size == right->st_size &&
        left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
        left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
        left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
        left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
}

static int directory_metadata(ErlNifEnv *env, const struct stat *status, ERL_NIF_TERM *map) {
    ERL_NIF_TERM keys[] = {atom(env, "device"), atom(env, "inode"), atom(env, "mode"),
        atom(env, "size"), atom(env, "mtime"), atom(env, "ctime")};
    ERL_NIF_TERM values[] = {
        enif_make_uint64(env, (ErlNifUInt64)status->st_dev),
        enif_make_uint64(env, (ErlNifUInt64)status->st_ino),
        enif_make_uint64(env, (ErlNifUInt64)status->st_mode),
        enif_make_int64(env, (ErlNifSInt64)status->st_size),
        enif_make_tuple2(env, enif_make_int64(env, (ErlNifSInt64)status->st_mtim.tv_sec),
            enif_make_int64(env, (ErlNifSInt64)status->st_mtim.tv_nsec)),
        enif_make_tuple2(env, enif_make_int64(env, (ErlNifSInt64)status->st_ctim.tv_sec),
            enif_make_int64(env, (ErlNifSInt64)status->st_ctim.tv_nsec))};
    return enif_make_map_from_arrays(env, keys, values, 6, map);
}

static ERL_NIF_TERM list_directory_bounded(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    ErlNifBinary path;
    unsigned entry_budget, byte_budget;
    if (!enif_inspect_binary(env, argv[0], &path) || path.size == 0 ||
        path.size > MAX_DIRECTORY_PATH || memchr(path.data, '\0', path.size))
        return error(env, "invalid_path");
    if (!enif_get_uint(env, argv[1], &entry_budget) || entry_budget > MAX_DIRECTORY_ENTRIES ||
        !enif_get_uint(env, argv[2], &byte_budget) || byte_budget > MAX_DIRECTORY_NAME_BYTES)
        return error(env, "invalid_budget");

    char pathname[MAX_DIRECTORY_PATH + 1];
    memcpy(pathname, path.data, path.size);
    pathname[path.size] = '\0';
    directory_read *read = enif_alloc(sizeof(*read));
    if (!read) return error(env, "enomem");
    read->allocated = 0;
    int fd = open(pathname, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        int failure = errno;
        enif_free(read);
        return system_error(env, failure);
    }

    struct stat before, after, path_status;
    const char *refusal = NULL;
    int failure = 0;
    unsigned examined = 0, name_bytes = 0, raw_records = 0, attempts = 0;
    if (fstat(fd, &before) < 0) {
        failure = errno;
        goto finished;
    }

    for (;;) {
        if (attempts >= entry_budget + 4) {
            refusal = "directory_work_limit";
            goto finished;
        }
        attempts++;
        ssize_t size = getdents64(fd, read->scratch, sizeof(read->scratch));
        if (size < 0) {
            if (errno == EINTR) continue;
            failure = errno;
            goto finished;
        }
        if (size == 0) break;
        if ((size_t)size > sizeof(read->scratch)) {
            refusal = "invalid_directory_entry";
            goto finished;
        }

        size_t position = 0;
        const size_t name_offset = offsetof(struct dirent64, d_name);
        while (position < (size_t)size) {
            if (raw_records >= entry_budget + 3) {
                refusal = "directory_work_limit";
                goto finished;
            }
            raw_records++;
            const unsigned char *record = read->scratch + position;
            size_t remaining = (size_t)size - position;
            unsigned short record_size;
            /* Read no field until the fixed header and one name byte fit.
               memcpy avoids an alignment assumption about an untrusted record. */
            if (remaining < name_offset + 1) {
                refusal = "invalid_directory_entry";
                goto finished;
            }
            memcpy(&record_size, record + offsetof(struct dirent64, d_reclen),
                sizeof(record_size));
            if (record_size < name_offset + 1 || record_size > remaining) {
                refusal = "invalid_directory_entry";
                goto finished;
            }
            const unsigned char *name = record + name_offset;
            const unsigned char *end = memchr(name, '\0', record_size - name_offset);
            if (!end || end == name || (size_t)(end - name) > MAX_DIRECTORY_NAME) {
                refusal = "invalid_directory_entry";
                goto finished;
            }
            size_t name_size = (size_t)(end - name);
            position += record_size;
            if ((name_size == 1 && name[0] == '.') ||
                (name_size == 2 && name[0] == '.' && name[1] == '.')) continue;

            /* All non-dot names are charged before filename allocation/copy;
               neither entry types nor suffixes grant uncharged work. */
            if (examined >= entry_budget) {
                refusal = "entry_limit";
                goto finished;
            }
            examined++;
            if (name_size > byte_budget - name_bytes) {
                refusal = "name_byte_limit";
                goto finished;
            }
            name_bytes += (unsigned)name_size;
            ErlNifBinary *binary = &read->names[read->allocated];
            if (!enif_alloc_binary(name_size, binary)) {
                refusal = "enomem";
                goto finished;
            }
            read->allocated++;
            memcpy(binary->data, name, name_size);
        }
    }

    if (fstat(fd, &after) < 0 || stat(pathname, &path_status) < 0) {
        failure = errno;
        goto finished;
    }
    if (!same_directory(&before, &after) || !same_directory(&after, &path_status))
        refusal = "directory_changed";

finished:
    /* Every post-open branch reaches exactly this close. Linux close is never
       retried, even for EINTR, and its error takes precedence over read errors. */
    {
        int close_failure = close_fd(fd);
        if (close_failure) failure = close_failure;
    }
    if (failure || refusal) {
        for (unsigned i = 0; i < read->allocated; i++) enif_release_binary(&read->names[i]);
        enif_free(read);
        return failure ? system_error(env, failure) : error(env, refusal);
    }

    ERL_NIF_TERM metadata[3], identity_map, result;
    ERL_NIF_TERM identity_keys[] = {atom(env, "before"), atom(env, "after"), atom(env, "path")};
    if (!directory_metadata(env, &before, &metadata[0]) ||
        !directory_metadata(env, &after, &metadata[1]) ||
        !directory_metadata(env, &path_status, &metadata[2]) ||
        !enif_make_map_from_arrays(env, identity_keys, metadata, 3, &identity_map)) {
        for (unsigned i = 0; i < read->allocated; i++) enif_release_binary(&read->names[i]);
        enif_free(read);
        return error(env, "enomem");
    }
    ERL_NIF_TERM names = enif_make_list(env, 0);
    for (unsigned i = read->allocated; i > 0; i--)
        names = enif_make_list_cell(env, enif_make_binary(env, &read->names[i - 1]), names);
    enif_free(read);
    ERL_NIF_TERM keys[] = {atom(env, "names"), atom(env, "examined"), atom(env, "name_bytes"),
        atom(env, "raw_records"), atom(env, "syscall_attempts"), atom(env, "identity")};
    ERL_NIF_TERM values[] = {names, enif_make_uint(env, examined), enif_make_uint(env, name_bytes),
        enif_make_uint(env, raw_records), enif_make_uint(env, attempts), identity_map};
    if (!enif_make_map_from_arrays(env, keys, values, 6, &result)) return error(env, "enomem");
    return enif_make_tuple2(env, atom(env, "ok"), result);
}

#define MAX_FILE_BYTES 1048576
#define FILE_READ_BYTES 4096

static int file_read_timestamp(ErlNifEnv *env, ERL_NIF_TERM value, struct timespec *stamp) {
    int arity;
    const ERL_NIF_TERM *parts;
    ErlNifSInt64 seconds, nanoseconds;
    if (!enif_get_tuple(env, value, &arity, &parts) || arity != 2 ||
        !enif_get_int64(env, parts[0], &seconds) ||
        !enif_get_int64(env, parts[1], &nanoseconds) ||
        nanoseconds < 0 || nanoseconds > 999999999) return 0;
    stamp->tv_sec = (time_t)seconds;
    stamp->tv_nsec = (long)nanoseconds;
    return 1;
}

static int file_read_directory_identity(ErlNifEnv *env, ERL_NIF_TERM value, struct stat *status) {
    size_t count;
    ERL_NIF_TERM fields[6];
    const char *keys[] = {"device", "inode", "mode", "size", "mtime", "ctime"};
    ErlNifUInt64 device, inode;
    ErlNifSInt64 size;
    unsigned mode;
    if (!enif_get_map_size(env, value, &count) || count != 6) return 0;
    for (unsigned i = 0; i < 6; i++)
        if (!enif_get_map_value(env, value, atom(env, keys[i]), &fields[i])) return 0;
    if (!enif_get_uint64(env, fields[0], &device) ||
        !enif_get_uint64(env, fields[1], &inode) ||
        !enif_get_uint(env, fields[2], &mode) || !S_ISDIR(mode) ||
        !enif_get_int64(env, fields[3], &size) || size < 0 ||
        !file_read_timestamp(env, fields[4], &status->st_mtim) ||
        !file_read_timestamp(env, fields[5], &status->st_ctim)) return 0;
    status->st_dev = (dev_t)device;
    status->st_ino = (ino_t)inode;
    status->st_mode = (mode_t)mode;
    status->st_size = (off_t)size;
    return 1;
}

/* This primitive preserves numeric filesystem errno values in its contract. */
static ERL_NIF_TERM file_read_system_error(ErlNifEnv *env, int value) {
    return enif_make_tuple2(env, atom(env, "error"),
        enif_make_tuple2(env, atom(env, "errno"), enif_make_int(env, value)));
}

static ERL_NIF_TERM read_file_at_bounded(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    ErlNifBinary path, name, bytes;
    unsigned byte_budget;
    struct stat expected = {0};
    if (!enif_inspect_binary(env, argv[0], &path) || path.size == 0 ||
        path.size > MAX_DIRECTORY_PATH || memchr(path.data, '\0', path.size))
        return error(env, "invalid_path");
    if (!enif_inspect_binary(env, argv[1], &name) || name.size == 0 ||
        name.size > MAX_DIRECTORY_NAME || memchr(name.data, '\0', name.size) ||
        memchr(name.data, '/', name.size) || (name.size == 1 && name.data[0] == '.') ||
        (name.size == 2 && name.data[0] == '.' && name.data[1] == '.'))
        return error(env, "invalid_name");
    if (!file_read_directory_identity(env, argv[2], &expected))
        return error(env, "invalid_identity");
    if (!enif_get_uint(env, argv[3], &byte_budget) || byte_budget > MAX_FILE_BYTES)
        return error(env, "invalid_budget");

    char pathname[MAX_DIRECTORY_PATH + 1], leaf[MAX_DIRECTORY_NAME + 1];
    memcpy(pathname, path.data, path.size);
    pathname[path.size] = '\0';
    memcpy(leaf, name.data, name.size);
    leaf[name.size] = '\0';
    int directory_fd = open(pathname, O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_CLOEXEC);
    if (directory_fd < 0) return file_read_system_error(env, errno);

    int file_fd = -1, allocated = 0, failure = 0;
    const char *refusal = NULL;
    struct stat directory_before, directory_after, directory_path;
    struct stat file_before, file_after, file_path;
    size_t used = 0;
    unsigned attempts = 0, attempt_budget = byte_budget / FILE_READ_BYTES + 4;
    if (fstat(directory_fd, &directory_before) < 0) {
        failure = errno;
        goto finished;
    }
    if (!same_directory(&expected, &directory_before)) {
        refusal = "directory_changed";
        goto finished;
    }
    /* Trusted directory/leaf symlinks are followed; lookup remains relative to
       this verified owned directory, held until all final identity checks. */
    file_fd = openat(directory_fd, leaf, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (file_fd < 0 || fstat(file_fd, &file_before) < 0) {
        failure = errno;
        goto finished;
    }
    if (!S_ISREG(file_before.st_mode)) {
        refusal = "not_regular_file";
        goto finished;
    }
    if (file_before.st_size < 0) {
        refusal = "file_changed";
        goto finished;
    }
    if ((ErlNifUInt64)file_before.st_size > byte_budget) {
        refusal = "file_byte_limit";
        goto finished;
    }
    if (!enif_alloc_binary((size_t)byte_budget + 1, &bytes)) {
        refusal = "enomem";
        goto finished;
    }
    allocated = 1;
    for (;;) {
        if (attempts >= attempt_budget) {
            refusal = "file_work_limit";
            goto finished;
        }
        size_t request = (size_t)byte_budget + 1 - used;
        if (request > FILE_READ_BYTES) request = FILE_READ_BYTES;
        attempts++;
        ssize_t received = read(file_fd, bytes.data + used, request);
        if (received < 0) {
            if (errno == EINTR) continue;
            failure = errno;
            goto finished;
        }
        if (received == 0) break;
        used += (size_t)received;
        if (used > byte_budget) {
            refusal = "file_byte_limit";
            goto finished;
        }
    }
    if (fstat(file_fd, &file_after) < 0 ||
        fstatat(directory_fd, leaf, &file_path, 0) < 0 ||
        fstat(directory_fd, &directory_after) < 0 || stat(pathname, &directory_path) < 0) {
        failure = errno;
        goto finished;
    }
    /* Files and directories share the same six-field metadata projection. */
    if (!same_directory(&file_before, &file_after) ||
        !same_directory(&file_after, &file_path) || used != (size_t)file_before.st_size)
        refusal = "file_changed";
    else if (!same_directory(&expected, &directory_after) ||
        !same_directory(&expected, &directory_path))
        refusal = "directory_changed";

finished:
    {
        int descriptors[] = {file_fd, directory_fd};
        int cleanup_failure = 0;
        for (unsigned i = 0; i < 2; i++) {
            if (descriptors[i] < 0) continue;
            int close_failure = close_fd(descriptors[i]);
            if (close_failure && !cleanup_failure) cleanup_failure = close_failure;
        }
        if (cleanup_failure) failure = cleanup_failure;
    }
    if (failure || refusal) {
        if (allocated) enif_release_binary(&bytes);
        return failure ? file_read_system_error(env, failure) : error(env, refusal);
    }

    ERL_NIF_TERM metadata[6], file_identity, directory_identity, result;
    const struct stat *statuses[] = {&file_before, &file_after, &file_path,
        &directory_before, &directory_after, &directory_path};
    for (unsigned i = 0; i < 6; i++) {
        if (!directory_metadata(env, statuses[i], &metadata[i])) {
            enif_release_binary(&bytes);
            return error(env, "enomem");
        }
    }
    ERL_NIF_TERM identity_keys[] = {atom(env, "before"), atom(env, "after"), atom(env, "path")};
    if (!enif_make_map_from_arrays(env, identity_keys, metadata, 3, &file_identity) ||
        !enif_make_map_from_arrays(env, identity_keys, metadata + 3, 3, &directory_identity)) {
        enif_release_binary(&bytes);
        return error(env, "enomem");
    }
    ERL_NIF_TERM keys[] = {atom(env, "bytes"), atom(env, "bytes_read"),
        atom(env, "syscall_attempts"), atom(env, "identity"), atom(env, "directory")};
    ERL_NIF_TERM values[] = {
        enif_make_sub_binary(env, enif_make_binary(env, &bytes), 0, used),
        enif_make_uint64(env, (ErlNifUInt64)used), enif_make_uint(env, attempts),
        file_identity, directory_identity};
    if (!enif_make_map_from_arrays(env, keys, values, 5, &result)) return error(env, "enomem");
    return enif_make_tuple2(env, atom(env, "ok"), result);
}

static int load(ErlNifEnv *env, void **priv, ERL_NIF_TERM info) {
    (void)priv; (void)info;
    fd_type = enif_open_resource_type(env, NULL, "gao_bus_owned_fd", destructor, ERL_NIF_RT_CREATE, NULL);
    return fd_type ? 0 : -1;
}
static ErlNifFunc functions[] = {
    {"inherited_listener_handoff", 1, inherited_listener_handoff, 0},
    {"capture", 1, capture_socket, 0},
    {"recv", 3, receive_rights, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"send", 3, send_rights, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"duplicate", 1, duplicate_resources, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"writable", 1, writable, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"close", 1, close_resource, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"info", 1, resource_info, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"identity", 0, identity, 0},
    {"list_dir_bounded", 3, list_directory_bounded, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"read_file_at_bounded", 4, read_file_at_bounded, ERL_NIF_DIRTY_JOB_IO_BOUND}
};
ERL_NIF_INIT(Elixir.GaoBus.Unix.Native, functions, load, NULL, NULL, NULL)
