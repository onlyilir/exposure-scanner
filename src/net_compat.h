#ifndef NET_COMPAT_H
#define NET_COMPAT_H

#include <stddef.h>

/* Tiny Winsock/POSIX wrapper. All blocking calls honour the timeout given. */

typedef long long net_sock;
#define NET_BAD (-1LL)

int net_init(void); /* idempotent; returns 0 on success */
void net_cleanup(void);

/* TCP connect with timeout; sets send/recv timeouts on the socket. NET_BAD on failure,
   message in err. */
net_sock net_connect(const char *host, const char *port, int timeout_ms, char *err,
                     size_t errlen);
int net_send_all(net_sock s, const char *buf, size_t n); /* 0 ok, -1 error */
int net_recv(net_sock s, char *buf, size_t n);           /* bytes, 0 = closed, -1 error/timeout */
void net_close(net_sock s);

/* Listening socket on 127.0.0.1 with an ephemeral port (used by the tests). */
net_sock net_listen_local(unsigned short *port_out);
net_sock net_accept(net_sock listener); /* sets 3 s timeouts on the new socket */

long long net_now_ms(void); /* monotonic */
void net_sleep_ms(long long ms);

#endif
