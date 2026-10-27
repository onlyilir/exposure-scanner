#include "net_compat.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET sock_t;
#define SOCK_INVALID INVALID_SOCKET
#define CLOSE_SOCK(s) closesocket(s)
#define LAST_WOULDBLOCK() (WSAGetLastError() == WSAEWOULDBLOCK)
#else
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
typedef int sock_t;
#define SOCK_INVALID (-1)
#define CLOSE_SOCK(s) close(s)
#define LAST_WOULDBLOCK() (errno == EINPROGRESS || errno == EWOULDBLOCK)
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static int g_init;

int net_init(void)
{
#ifdef _WIN32
    WSADATA wsa;

    if (g_init)
        return 0;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return -1;
#endif
    g_init = 1;
    return 0;
}

void net_cleanup(void)
{
#ifdef _WIN32
    if (g_init)
        WSACleanup();
#endif
    g_init = 0;
}

static void set_err(char *err, size_t errlen, const char *what, const char *detail)
{
    if (err != NULL && errlen > 0)
        snprintf(err, errlen, "%s%s%s", what, detail != NULL ? ": " : "", detail != NULL ? detail : "");
}

static int set_nonblocking(sock_t s, int on)
{
#ifdef _WIN32
    u_long mode = on ? 1 : 0;

    return ioctlsocket(s, FIONBIO, &mode);
#else
    int fl = fcntl(s, F_GETFL, 0);

    if (fl < 0)
        return -1;
    return fcntl(s, F_SETFL, on ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK));
#endif
}

static void set_timeouts(sock_t s, int ms)
{
#ifdef _WIN32
    DWORD t = (DWORD)ms;

    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&t, sizeof t);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&t, sizeof t);
#else
    struct timeval tv;

    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
#endif
}

net_sock net_connect(const char *host, const char *port, int timeout_ms, char *err, size_t errlen)
{
    struct addrinfo hints, *res = NULL, *ai;
    int rc;
    const char *last = "no address";

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        set_err(err, errlen, "dns lookup failed", gai_strerror(rc));
        return NET_BAD;
    }
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        sock_t s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        fd_set wf;
        struct timeval tv;
        int soerr = 0;
        socklen_t sl = sizeof soerr;

        if (s == SOCK_INVALID) {
            last = "socket() failed";
            continue;
        }
        if (set_nonblocking(s, 1) != 0) {
            CLOSE_SOCK(s);
            continue;
        }
        rc = connect(s, ai->ai_addr, (int)ai->ai_addrlen);
        if (rc != 0 && !LAST_WOULDBLOCK()) {
            last = "connection refused or unreachable";
            CLOSE_SOCK(s);
            continue;
        }
        if (rc != 0) {
            FD_ZERO(&wf);
            FD_SET(s, &wf);
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            rc = select((int)s + 1, NULL, &wf, NULL, &tv);
            if (rc <= 0) {
                last = rc == 0 ? "connect timed out" : "select() failed";
                CLOSE_SOCK(s);
                continue;
            }
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &sl) != 0 || soerr != 0) {
                last = "connection refused or unreachable";
                CLOSE_SOCK(s);
                continue;
            }
        }
        set_nonblocking(s, 0);
        set_timeouts(s, timeout_ms);
        freeaddrinfo(res);
        return (net_sock)s;
    }
    freeaddrinfo(res);
    set_err(err, errlen, last, NULL);
    return NET_BAD;
}

int net_send_all(net_sock s, const char *buf, size_t n)
{
    size_t done = 0;

    while (done < n) {
        int w = (int)send((sock_t)s, buf + done, (int)(n - done), MSG_NOSIGNAL);

        if (w <= 0)
            return -1;
        done += (size_t)w;
    }
    return 0;
}

int net_recv(net_sock s, char *buf, size_t n)
{
    int r = (int)recv((sock_t)s, buf, (int)n, 0);

    return r < 0 ? -1 : r;
}

void net_close(net_sock s)
{
    if (s != NET_BAD)
        CLOSE_SOCK((sock_t)s);
}

net_sock net_listen_local(unsigned short *port_out)
{
    sock_t s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    int one = 1;

    if (s == SOCK_INVALID)
        return NET_BAD;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0 || listen(s, 16) != 0 ||
        getsockname(s, (struct sockaddr *)&a, &al) != 0) {
        CLOSE_SOCK(s);
        return NET_BAD;
    }
    *port_out = ntohs(a.sin_port);
    return (net_sock)s;
}

net_sock net_accept(net_sock listener)
{
    sock_t c = accept((sock_t)listener, NULL, NULL);

    if (c == SOCK_INVALID)
        return NET_BAD;
    set_timeouts(c, 3000);
    return (net_sock)c;
}

long long net_now_ms(void)
{
#ifdef _WIN32
    return (long long)GetTickCount64();
#else
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

void net_sleep_ms(long long ms)
{
    if (ms <= 0)
        return;
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    {
        struct timespec ts;

        ts.tv_sec = (time_t)(ms / 1000);
        ts.tv_nsec = (long)(ms % 1000) * 1000000L;
        nanosleep(&ts, NULL);
    }
#endif
}
