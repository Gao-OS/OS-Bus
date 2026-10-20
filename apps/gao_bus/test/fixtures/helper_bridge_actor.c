#define _GNU_SOURCE
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#ifndef FIXTURE_DIRECTORY
#error Fixture builds require a private directory
#endif

extern char **environ;

int main(int argc, char **argv) {
    if (argc != 2) return 99;
    const char *name = argv[1];
    const char *exit_code = strstr(name, ".Exit");
    if (exit_code) return atoi(exit_code + 5);
    if (!strcmp(name, "org.fixture.Kill")) { raise(SIGKILL); return 98; }
    if (!strcmp(name, "org.fixture.Term")) { raise(SIGTERM); return 98; }
    if (!strcmp(name, "org.fixture.Inspect")) {
        int bad = 0;
        if (*environ != NULL) bad |= 1;
        DIR *directory = opendir("/proc/self/fd");
        if (!directory) return 92;
        struct dirent *entry;
        while ((entry = readdir(directory))) {
            if (entry->d_name[0] == '.') continue;
            int fd = atoi(entry->d_name);
            if (fd > 2 && fd != dirfd(directory)) bad |= 2;
        }
        closedir(directory);
        char path[64];
        for (int fd = 0; fd <= 2; fd++) {
            snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
            char target[128] = {0};
            if (readlink(path, target, sizeof(target) - 1) < 0 || strcmp(target, "/dev/null")) bad |= 4;
        }
        struct rlimit limit;
        if (getrlimit(RLIMIT_CORE, &limit) || limit.rlim_cur != 0 || limit.rlim_max != 0) bad |= 8;
        struct sigaction action;
        sigset_t mask;
        if (sigaction(SIGTERM, NULL, &action) || action.sa_handler != SIG_DFL) bad |= 16;
        if (sigprocmask(SIG_SETMASK, NULL, &mask) || sigismember(&mask, SIGTERM)) bad |= 32;
        if (write(4, "hostile", 7) != -1 || errno != EBADF) bad |= 64;
        return bad;
    }
    if (!strcmp(name, "org.fixture.Flood")) {
        char bytes[8192]; memset(bytes, 'x', sizeof(bytes));
        for (int i = 0; i < 1024; i++) {
            if (write(1, bytes, sizeof(bytes)) != sizeof(bytes) ||
                write(2, bytes, sizeof(bytes)) != sizeof(bytes)) return 97;
        }
        return 0;
    }
    if (!strcmp(name, "org.fixture.Daemon")) {
        pid_t child = fork();
        if (child < 0) return 96;
        if (child != 0) return 0;
        FILE *file = fopen(FIXTURE_DIRECTORY "/daemon.pid", "w");
        if (!file) _exit(95);
        fprintf(file, "%d", getpid()); fclose(file);
        int fd = open(FIXTURE_DIRECTORY "/daemon.gate", O_RDONLY);
        char byte;
        if (fd < 0 || read(fd, &byte, 1) != 1) _exit(94);
        close(fd); _exit(0);
    }
    return 93;
}
