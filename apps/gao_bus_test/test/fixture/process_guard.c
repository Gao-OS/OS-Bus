/* Test-only process guardian: a closed runner lifeline terminates and reaps
 * the private child process group. It never opens a D-Bus address itself. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;

static void stop_signal(int signal_number) {
  (void)signal_number;
  stopping = 1;
}

static long monotonic_ms(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return -1;
  return now.tv_sec * 1000L + now.tv_nsec / 1000000L;
}

static void reap_group(pid_t child) {
  /* Keep the leader's zombie until after group signalling, preventing reuse
   * of its PID while the guardian still addresses the process group. */
  kill(-child, SIGTERM);
  long deadline = monotonic_ms() + 500;
  siginfo_t info;
  while (monotonic_ms() < deadline) {
    info.si_pid = 0;
    if (waitid(P_PID, child, &info, WEXITED | WNOHANG | WNOWAIT) == 0 && info.si_pid) break;
    poll(NULL, 0, 10);
  }
  kill(-child, SIGKILL);
}

int main(int argc, char **argv) {
  if (argc < 2) return 64;
  if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0) { perror("subreaper"); return 70; }
  struct sigaction action = {.sa_handler = stop_signal};
  sigemptyset(&action.sa_mask);
  sigaction(SIGTERM, &action, NULL);
  sigaction(SIGINT, &action, NULL);
  int barrier[2];
  if (pipe2(barrier, O_CLOEXEC) < 0) return 70;
  pid_t child = fork();
  if (child < 0) return 70;
  if (child == 0) {
    close(barrier[1]);
    if (setpgid(0, 0) < 0) _exit(70);
    char ready;
    if (read(barrier[0], &ready, 1) != 1) _exit(70);
    close(barrier[0]);
    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    int nullfd = open("/dev/null", O_RDONLY);
    if (nullfd < 0 || dup2(nullfd, STDIN_FILENO) < 0) _exit(70);
    if (nullfd != STDIN_FILENO) close(nullfd);
    execvp(argv[1], argv + 1);
    perror("execvp");
    _exit(127);
  }
  close(barrier[0]);
  if (setpgid(child, child) < 0 && errno != EACCES) {
    kill(child, SIGKILL); waitpid(child, NULL, 0); return 70;
  }
  printf("E2E_CHILD_PID %ld\n", (long)child);
  fflush(stdout);
  if (write(barrier[1], "1", 1) != 1) stopping = 1;
  close(barrier[1]);

  while (!stopping) {
    siginfo_t info = {0};
    if (waitid(P_PID, child, &info, WEXITED | WNOHANG | WNOWAIT) < 0) break;
    if (info.si_pid) break;
    struct pollfd lifeline = {.fd = STDIN_FILENO, .events = POLLIN | POLLHUP};
    int result = poll(&lifeline, 1, 50);
    if (result < 0 && errno != EINTR) break;
    if (lifeline.revents & (POLLHUP | POLLERR | POLLNVAL)) break;
    if (lifeline.revents & POLLIN) {
      char data[32];
      /* Any lifeline command, or EOF, requests shutdown. Child stdin is
       * deliberately /dev/null rather than this ownership channel. */
      ssize_t amount = read(STDIN_FILENO, data, sizeof(data));
      if (amount < 0 && errno == EINTR) continue;
      break;
    }
  }
  reap_group(child);
  int status;
  while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return 70;
  /* The subreaper also collects descendants from the terminated private group. */
  while (waitpid(-1, NULL, 0) > 0 || errno == EINTR) {}
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  return 70;
}
