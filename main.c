#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <fcntl.h>
#include <poll.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define SOCKET_PATH_ENV "DOCKINOUT_SOCKET_PATH"
#define SOCKET_PREFIX "/tmp/dockinout"
#define SOCKET_REPLACE_TOKEN "@@"

#define member_size(type, member) (sizeof ((type *) 0)->member)

static struct {
    char printf_buf[256];
    const char *program_path;
    sigset_t blocked_signals;
    sigset_t initial_signal_mask;
    int signal_fd;
    float opt_timeout;
    struct timespec timeout_deadline;
    char socket_path[member_size(struct sockaddr_un, sun_path)];
    char **command;
    size_t command_length;

    bool is_client;
    struct {
        bool unlink_socket;
    } server;
} dt;

void init_dt(char *argv[])
{
    dt.program_path = argv[0];
    sigemptyset(&dt.blocked_signals);
    dt.signal_fd = -1;
    dt.opt_timeout = -1.0;
}

__attribute__ ((noreturn))
void cleanup_and_exit(int code) {
    if (!dt.is_client) {
        if (dt.server.unlink_socket) {
            (void) unlink(dt.socket_path);
        }
    }
    _Exit(code);
}

const char *get_log_name()
{
    const char *last_slash = strrchr(dt.program_path, '/');
    return last_slash ? last_slash + 1 : dt.program_path;
}

#define bad_io(...) do { \
    int saved_errno = errno; \
    size_t n; \
    n = (size_t) snprintf( \
        dt.printf_buf, sizeof dt.printf_buf, \
        "%s:%s:%d:%s: failed ", \
        get_log_name(), __FILE__, __LINE__, __func__\
    ); \
    if (n > sizeof dt.printf_buf) \
        n = sizeof dt.printf_buf; \
    n += (size_t) snprintf( \
        dt.printf_buf + n, sizeof dt.printf_buf - n,  __VA_ARGS__ \
    ); \
    if (n > sizeof dt.printf_buf) \
        n = sizeof dt.printf_buf; \
    if (saved_errno) { \
        n += (size_t) snprintf( \
            dt.printf_buf + n, sizeof dt.printf_buf - n, \
            " errno=%d - %s", errno, strerror(saved_errno) \
        ); \
        if (n > sizeof dt.printf_buf) \
            n = sizeof dt.printf_buf; \
    } \
    if (n < sizeof dt.printf_buf) { \
        dt.printf_buf[n] = '\n'; \
        ++n; \
    } \
    write(2, dt.printf_buf, n); \
    cleanup_and_exit(1); \
} while (false)

static void do_log(char *title, const char *format, va_list ap)
{
    size_t cursor = 0;

#define append(str) do { \
    size_t n = strlen(str); \
    if (n > sizeof dt.printf_buf - cursor) { \
        n = sizeof dt.printf_buf - cursor; \
    } \
    memcpy(dt.printf_buf + cursor, str, n); \
    cursor += n; \
} while (false)

    append(get_log_name());
    append(": ");
    if (title) {
        append("[");
        append(title);
        append("] ");
    }

    int n = vsnprintf(
        dt.printf_buf + cursor, sizeof dt.printf_buf - cursor,
        format, ap
    );
    if (n < (int) (sizeof dt.printf_buf - cursor)) {
        cursor += (size_t) n;
    } else {
        cursor = sizeof dt.printf_buf;
    }

    append("\n");
#undef append

    write(2, dt.printf_buf, cursor);
}

__attribute__ ((format (printf, 1, 2)))
void fail(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    do_log("fail", format, ap);
    va_end(ap);
    cleanup_and_exit(1);
}

__attribute__ ((format (printf, 1, 2)))
void warn(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    do_log("warn", format, ap);
    va_end(ap);
}

__attribute__ ((format (printf, 1, 2)))
void usage_error(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    do_log("fail", format, ap);
    va_end(ap);
    cleanup_and_exit(1);
}

void *xmalloc(size_t size)
{
    assert(size != 0);
    void *p = malloc(size);
    if (!p) {
        const char *msg = "failed malloc\n";
        write(2, msg, strlen(msg));
        cleanup_and_exit(1);
    }
    return p;
}

static void setup()
{
    assert(dt.signal_fd == -1);
    sigaddset(&dt.blocked_signals, SIGTERM);
    sigaddset(&dt.blocked_signals, SIGHUP);
    sigaddset(&dt.blocked_signals, SIGINT);

    int status = sigprocmask(SIG_BLOCK, &dt.blocked_signals, &dt.initial_signal_mask);
    if (status != 0)
        bad_io("sigprocmask SIGCHLD status=%d", status);
    dt.signal_fd = signalfd(-1, &dt.blocked_signals, SFD_NONBLOCK | SFD_CLOEXEC);
    if (dt.signal_fd < 0)
        bad_io("signalfd fd=%d", dt.signal_fd);

    struct timespec time_result;
    status = clock_gettime(CLOCK_MONOTONIC, &time_result);
    if (status != 0)
        bad_io("clock_gettime CLOCK_MONOTONIC");

    double timeout_seconds = (time_t) floor(dt.opt_timeout);
    long timeout_nanos = (long) round((dt.opt_timeout - floor(dt.opt_timeout)) * 1.e9);
    dt.timeout_deadline.tv_sec = time_result.tv_sec + timeout_seconds;
    dt.timeout_deadline.tv_nsec = time_result.tv_nsec + timeout_nanos;
    if (dt.timeout_deadline.tv_nsec >= 1000 * 1000 * 1000) {
        dt.timeout_deadline.tv_sec += 1;
        dt.timeout_deadline.tv_nsec -= 1000 * 1000 * 1000;
    }
}

static void drain_signal_fd()
{
    for (;;) {
        struct signalfd_siginfo info;
        ssize_t nread = read(dt.signal_fd, &info, sizeof info);
        if (nread == sizeof info) {
            if (info.ssi_signo == SIGTERM
                || info.ssi_signo == SIGHUP
                || info.ssi_signo == SIGINT) {
                cleanup_and_exit(1);
            }
            continue;
        }
        if (nread == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
        bad_io("read signal_fd nread=%zd", nread);
    }
}

static void run_poll(int fd, short poll_events)
{
    assert(dt.signal_fd >= 0);
    struct pollfd polls[2];
    polls[0].fd = dt.signal_fd;
    polls[0].events = POLLIN;
    int npolls = 1;
    if (fd >= 0) {
        polls[1].fd = fd;
        polls[1].events = poll_events;
        ++npolls;
    }
    for (;;) {
        struct timespec time_current;
        int status = clock_gettime(CLOCK_MONOTONIC, &time_current);
        if (status != 0)
            bad_io("clock_gettime CLOCK_MONOTONIC");
        struct timespec timeout = {
            .tv_sec = dt.timeout_deadline.tv_sec - time_current.tv_sec,
            .tv_nsec = dt.timeout_deadline.tv_nsec - time_current.tv_nsec,
        };
        if (timeout.tv_nsec < 0) {
            timeout.tv_nsec += 1000 * 1000 * 1000;
            timeout.tv_sec -= 1;
        }
        if (timeout.tv_sec < 0) {
            fail("timed out waiting for IO");
        }

        for (int i = 0; i != npolls; ++i) {
            polls[i].revents = 0;
        }
        status = ppoll(polls, npolls, &timeout, NULL);
        if (1 <= status && status <= npolls) {
            if (polls[0].revents) {
                drain_signal_fd();
                if (fd < 0)
                    break;
            }
            if (fd >= 0 && polls[1].revents)
                break;
            continue;
        }
        if (status == 0) {
            // Let the above time check to report the timeout.
            continue;
        }
        if (status == -1 && errno == EINTR)
            continue;
        bad_io("ppoll status=%d", status);
    }
}


static socklen_t init_server_socket_address(struct sockaddr_un *addr)
{
    memset(addr, 0, sizeof(struct sockaddr_un));
    addr->sun_family = AF_UNIX;
    size_t socket_path_length = strlen(dt.socket_path);
    memcpy(addr->sun_path, dt.socket_path, socket_path_length + 1);
    return offsetof(struct sockaddr_un, sun_path) + socket_path_length;
}

#define FD_SENDING_COUNT ((size_t) 3)

typedef int msg_fd_data_t[FD_SENDING_COUNT];

typedef struct {
    struct msghdr msg;
    union {
        struct cmsghdr cmsg;
        uint8_t cmsg_space[CMSG_SPACE(sizeof(msg_fd_data_t))];
    };
    struct iovec payload_vec;
    char payload;
} msg_fd_t;

static void init_msg_fd(msg_fd_t *m)
{
    memset(m, 0, sizeof(msg_fd_t));
    m->payload_vec.iov_base = &m->payload;
    m->payload_vec.iov_len = sizeof(m->payload);
    m->msg.msg_iov = &m->payload_vec;
    m->msg.msg_iovlen = 1;
    m->msg.msg_control = &m->cmsg;
    m->msg.msg_controllen = sizeof m->cmsg_space;
}

__attribute__ ((noreturn))
static void do_exec()
{
    char **exec_cmd = xmalloc((dt.command_length + 1) * sizeof(char *));
    memcpy(exec_cmd, dt.command, dt.command_length * sizeof(char *));
    exec_cmd[dt.command_length] = NULL;

    assert(dt.signal_fd >= 0);
    int status = sigprocmask(SIG_SETMASK, &dt.initial_signal_mask, NULL);
    if (status != 0)
        bad_io("sigprocmask SIGCHLD status=%d", status);

    (void) execvp(exec_cmd[0], exec_cmd);
    bad_io("execvp %s", exec_cmd[0]);
}

static void client()
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        bad_io("socket");

    struct sockaddr_un addr;
    socklen_t addrlen = init_server_socket_address(&addr);
    for (bool connect_in_progress = false;;) {
        if (!connect_in_progress) {
            int status = connect(fd, (struct sockaddr *) &addr, addrlen);
            if (status == 0)
                break;
            if (errno == EINTR) {
                // This probably should never happen as socker is non-blocking.
                continue;
            }
            if (errno == EINPROGRESS) {
                connect_in_progress = true;
                continue;
            }
        } else {
            run_poll(fd, POLLOUT);
            int connect_errno;
            socklen_t option_size = sizeof(connect_errno);
            int status = getsockopt(
                fd, SOL_SOCKET, SO_ERROR, &connect_errno, &option_size
            );
            if (status != 0 || option_size != sizeof(connect_errno))
                bad_io("getsockopt option_size=%u", option_size);
            if (connect_errno == 0)
                break;
            if (connect_errno == EINPROGRESS)
                continue;
            errno = connect_errno;
        }
        fail("failed to connect to %s - %s", dt.socket_path, strerror(errno));
    }

    msg_fd_t msg_fd;
    init_msg_fd(&msg_fd);
    for (;;) {
        run_poll(fd, POLLIN);
        ssize_t nreceived = recvmsg(fd, &msg_fd.msg, 0);
        if (nreceived == 1) break;
        if (nreceived == 0) continue;
        if (nreceived != -1)
            bad_io("unexpected recvmsg result - %zd", nreceived);
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            continue;
        fail("cannot receive file descriptor message - %s", strerror(errno));
    }

    if (msg_fd.payload != 0)
        fail("socket descriptor message payload is not zero - %d", (int) msg_fd.payload);

    static const char error_prefix[] = "invalid format of auxiliary data";
    msg_fd_data_t descriptors;

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg_fd.msg);
    if (!cmsg)
        fail("%s - no data", error_prefix);
    if (cmsg->cmsg_level != SOL_SOCKET)
        fail("%s - bad level %d", error_prefix, cmsg->cmsg_level);
    if (cmsg->cmsg_type != SCM_RIGHTS)
        fail("%s - bad type %d", error_prefix, cmsg->cmsg_type);
    if (cmsg->cmsg_len != CMSG_LEN(sizeof(descriptors)))
    if (cmsg->cmsg_len != CMSG_LEN(sizeof(descriptors)))
        fail("%s - bad length %zd", error_prefix, cmsg->cmsg_len);
    memcpy(descriptors, CMSG_DATA(&msg_fd.cmsg), sizeof(descriptors));

    cmsg = CMSG_NXTHDR(&msg_fd.msg, cmsg);
    if (cmsg)
        fail("%s - extra_data", error_prefix);

    int status = close(fd);
    if (status != 0)
        bad_io("close fd=%d status=%d", fd, status);

    for (size_t i = 0; i != FD_SENDING_COUNT; ++i) {
        int fd = dup2(descriptors[i], (int) i);
        if (fd != (int) i) {
            bad_io("dup2 i=%zu fd=%d", i, fd);
        }
        status = close(descriptors[i]);
        if (status != 0)
            bad_io("close fd=%d status=%d", descriptors[i], status);
    }

    do_exec();
}

static int bind_and_listen()
{
    struct stat sb;
    int status = lstat(dt.socket_path, &sb);
    if (status < 0) {
        if (errno != ENOENT && errno != EACCES)
            fail("cannot stat %s - %s", dt.socket_path, strerror(errno));
    } else {
        if ((sb.st_mode & S_IFMT) != S_IFSOCK) {
            fail(
                "%s already exists and is not a socket",
                dt.socket_path
            );
        }

        warn("removing preexisting socket %s", dt.socket_path);
        status = unlink(dt.socket_path);
        if (status < 0) {
            fail(
                "failed to remove preexisting socket %s - %s",
                dt.socket_path, strerror(errno)
            );
        }
    }

    int socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (socket_fd < 0)
        bad_io("socket");

    struct sockaddr_un addr;
    socklen_t addrlen = init_server_socket_address(&addr);
    status = bind(socket_fd, (struct sockaddr *) &addr, addrlen);
    if (status < 0) {
        fail(
            "cannot bind socket to %s - %s",
            dt.socket_path, strerror(errno)
        );
    }

    dt.server.unlink_socket = true;

    status = listen(socket_fd, 1);
    if (status != 0)
        bad_io("listen %s", dt.socket_path);
    return socket_fd;
}

static void server()
{
    pid_t child_pid = fork();
    if (child_pid == -1)
        bad_io("fork");

    if (child_pid != 0) {
        assert(dt.signal_fd >= 0);
        sigaddset(&dt.blocked_signals, SIGCHLD);
        int status = sigprocmask(SIG_BLOCK, &dt.blocked_signals, NULL);
        if (status != 0)
            bad_io("sigprocmask SIGCHLD status=%d", status);
        status = signalfd(dt.signal_fd, &dt.blocked_signals, 0);
        if (status != dt.signal_fd)
            bad_io("signalfd status=%d", status);

        // Wait until server sets up connections
        int child_status;
        for (;;) {
            // call this before run_poll to cover the case when SIGCHLD
            // was issued before the signal was blocked.
            int waitpid_result = waitpid(child_pid, &child_status, WNOHANG);
            if (waitpid_result == child_pid)
                break;
            if (waitpid_result != 0) {
                if (waitpid_result != -1)
                    bad_io("waitpid result=%d", waitpid_result);
                if (errno != EINTR)
                bad_io("waitpid result=%d", child_pid);
            }
            run_poll(-1, 0);
        }

        if (WIFEXITED(child_status)) {
            if (WEXITSTATUS(child_status) != 0) {
                fail(
                    "child process exited with error %d",
                    WEXITSTATUS(child_status)
                );
            }
        } else {
            fail("child was killed and core-dumped");
        }

        // Redirect stdin and stdout to null, but keep stderr as is
        // so errors from invocation of the program goes to the
        // original stderr.

        for (int fd = 0; fd <= 1; ++fd) {
            int open_mode = (fd == 0) ? O_RDONLY : O_WRONLY;
            int dev_null = open("/dev/null", open_mode);
            if (dev_null == -1) {
                const char *mode_str = (fd == 0) ? "reading" : "writing";
                fail("failed to open /dev/null for %s - %s", mode_str, strerror(errno));
            }
            int fd_copy = dup2(dev_null, fd);
            if (fd_copy != fd)
                bad_io("dup2 from=%d to=%d result=%d", dev_null, fd, fd_copy);
            int status = close(dev_null);
            if (status != 0)
                bad_io("close fd=%d status=%d", dev_null, status);
        }

        // Replace socket path tokens in the command arguments.
        for (size_t i = 1; i != dt.command_length; ++i) {
            const char *arg = dt.command[i];
            char *buffer = NULL;
            size_t cursor = 0;
            for (;;) {
                const char *found = strstr(arg, SOCKET_REPLACE_TOKEN);
                if (!found) {
                    size_t n = strlen(arg) + 1;
                    if (!buffer) {
                        if (cursor != 0) {
                            arg = dt.command[i];
                            buffer = xmalloc(cursor + n);
                            cursor = 0;
                            continue;
                        }
                    } else {
                        memcpy(buffer + cursor, arg, n);
                        dt.command[i] = buffer;
                    }
                    break;
                }
                if (buffer) {
                    memcpy(buffer + cursor, arg, found - arg);
                    memcpy(
                        buffer + cursor + (found - arg),
                        dt.socket_path,
                        strlen(dt.socket_path)
                    );
                }
                cursor += (found - arg) + strlen(dt.socket_path);
                arg = found + strlen(SOCKET_REPLACE_TOKEN);
            }
        }

        status = setenv(SOCKET_PATH_ENV, dt.socket_path, 1);
        if (status != 0)
            bad_io("setenv status=%d env=%s", status, SOCKET_PATH_ENV);

        do_exec();
    }

    int server_fd = bind_and_listen();

    // Double-fork to signal the parent we are ready for connections.
    pid_t server_pid = fork();
    if (server_pid == -1)
        bad_io("fork");

    if (server_pid) {
        // Direct exit without cleanup
        _Exit(0);
    }

    // wait for client to connect
    int client_fd;
    for (;;) {
        run_poll(server_fd, POLLIN);
        client_fd = accept4(server_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (client_fd != -1)
            break;
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            continue;
        bad_io("accept4 %s", dt.socket_path);
    }

    msg_fd_data_t descriptors;
    for (size_t i = 0; i != FD_SENDING_COUNT; ++i) {
        descriptors[i] = (int) i;
    }

    msg_fd_t msg_fd;
    init_msg_fd(&msg_fd);
    msg_fd.cmsg.cmsg_len = CMSG_LEN(sizeof(descriptors));
    msg_fd.cmsg.cmsg_level = SOL_SOCKET;
    msg_fd.cmsg.cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(&msg_fd.cmsg), descriptors, sizeof(descriptors));

    for (;;) {
        run_poll(client_fd, POLLOUT);
        ssize_t nsent = sendmsg(client_fd, &msg_fd.msg, 0);
        if (nsent == 1)
            break;
        if (nsent == 0)
            continue;
        if (nsent != -1)
            bad_io("unexpected sendmsg result - %zd", nsent);
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            continue;
        fail("cannot send file descriptor message - %s", strerror(errno));
    }

    int status = close(client_fd);
    if (status != 0)
        bad_io("close client %d", client_fd);

    int close_status = close(server_fd);
    if (close_status != 0)
        bad_io("close %d", server_fd);

    fprintf(stderr, "server done\n");
}

int main(int argc, char* argv[])
{
    init_dt(argv);

    int opt;
    while ((opt = getopt(argc, argv, "+:c:t:")) != -1) {
        switch (opt) {
        case 'c': {
            size_t n = strlen(optarg);
            if (n >= sizeof dt.socket_path) {
                usage_error(
                    "too long path for -%c option - %.200s",
                    (char) opt, optarg
                );
            }
            memcpy(dt.socket_path, optarg, n + 1);
            dt.is_client = true;
            break;
        }
        case 't': {
            char *endptr;
            errno = 0;
            double v = strtod(optarg, &endptr);
            if (errno || endptr == optarg || *endptr != '\0' || v < 0.0 || v > 1.0e6) {
                usage_error(
                    "the argument of %c option is not a valid timeout - '%s'",
                    (char) opt, optarg
                );
            }
            dt.opt_timeout = v;
            break;
        }
        case '?':
            usage_error("unknown option -%c", (char) optopt);
            break;
        case ':':
            usage_error("option -%c requires an argument", (char) optopt);
            break;
        }
    }
    if (optind == argc) {
        usage_error("missing command name argument");
    }

    dt.command = argv + optind;
    dt.command_length = argc - optind;

    if (dt.opt_timeout < 0.0) {
        // In server allow time to enter password when the command uses
        // sudo. With client allow for a busy system.
        dt.opt_timeout = dt.is_client ? 5.0 : 60.0;
    }

    setup();

    if (dt.is_client) {
        client();
    } else {
        pid_t pid = getpid();
        size_t socket_path_length = (size_t) snprintf(
            dt.socket_path, sizeof dt.socket_path,
            "%s.%d", SOCKET_PREFIX, pid);
        if (socket_path_length >= sizeof dt.socket_path)
            fail("too long socket prefix - %.200s", SOCKET_PREFIX);

        server();
    }

    cleanup_and_exit(0);
}
