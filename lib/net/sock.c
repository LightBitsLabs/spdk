/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "spdk/stdinc.h"

#if defined(__linux__)
#include <sys/epoll.h>
#elif defined(__FreeBSD__)
#include <sys/event.h>
#endif

#include "spdk/log.h"
#include "spdk/sock.h"
#include "spdk/queue.h"

#define MAX_TMPBUF 1024
#define PORTNUMLEN 32

#define MAX_EVENTS_PER_POLL 32

struct spdk_sock {
	int			fd;
	spdk_sock_cb		cb_fn;
	void			*cb_arg;
	TAILQ_ENTRY(spdk_sock)	link;
};

struct spdk_sock_group {
	int			fd;
	TAILQ_HEAD(, spdk_sock)	socks;
};

static int get_addr_str(struct sockaddr *sa, char *host, size_t hlen)
{
	const char *result = NULL;

	if (sa == NULL || host == NULL) {
		return -1;
	}

	switch (sa->sa_family) {
	case AF_INET:
		result = inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
				   host, hlen);
		break;
	case AF_INET6:
		result = inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
				   host, hlen);
		break;
	default:
		break;
	}

	if (result != NULL) {
		return 0;
	} else {
		return -1;
	}
}

static int
spdk_posix_sock_getaddr(struct spdk_sock *sock, char *saddr, int slen, char *caddr, int clen)
{
	struct sockaddr_storage sa;
	socklen_t salen;
	int rc;

	assert(sock != NULL);

	memset(&sa, 0, sizeof sa);
	salen = sizeof sa;
	rc = getsockname(sock->fd, (struct sockaddr *) &sa, &salen);
	if (rc != 0) {
		SPDK_ERRLOG("getsockname() failed (errno=%d)\n", errno);
		return -1;
	}

	switch (sa.ss_family) {
	case AF_UNIX:
		/* Acceptable connection types that don't have IPs */
		return 0;
	case AF_INET:
	case AF_INET6:
		/* Code below will get IP addresses */
		break;
	default:
		/* Unsupported socket family */
		return -1;
	}

	rc = get_addr_str((struct sockaddr *)&sa, saddr, slen);
	if (rc != 0) {
		SPDK_ERRLOG("getnameinfo() failed (errno=%d)\n", errno);
		return -1;
	}

	memset(&sa, 0, sizeof sa);
	salen = sizeof sa;
	rc = getpeername(sock->fd, (struct sockaddr *) &sa, &salen);
	if (rc != 0) {
		SPDK_ERRLOG("getpeername() failed (errno=%d)\n", errno);
		return -1;
	}

	rc = get_addr_str((struct sockaddr *)&sa, caddr, clen);
	if (rc != 0) {
		SPDK_ERRLOG("getnameinfo() failed (errno=%d)\n", errno);
		return -1;
	}

	return 0;
}

enum spdk_posix_sock_create_type {
	SPDK_SOCK_CREATE_LISTEN,
	SPDK_SOCK_CREATE_CONNECT,
};

static struct spdk_sock *
spdk_posix_sock_create(const char *ip, int port, enum spdk_posix_sock_create_type type)
{
	struct spdk_sock *sock;
	char buf[MAX_TMPBUF];
	char portnum[PORTNUMLEN];
	char *p;
	struct addrinfo hints, *res, *res0;
	int fd, flag;
	int val = 1;
	int rc;

	if (ip == NULL) {
		return NULL;
	}
	if (ip[0] == '[') {
		snprintf(buf, sizeof(buf), "%s", ip + 1);
		p = strchr(buf, ']');
		if (p != NULL) {
			*p = '\0';
		}
		ip = (const char *) &buf[0];
	}

	snprintf(portnum, sizeof portnum, "%d", port);
	memset(&hints, 0, sizeof hints);
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;
	hints.ai_flags |= AI_PASSIVE;
	hints.ai_flags |= AI_NUMERICHOST;
	rc = getaddrinfo(ip, portnum, &hints, &res0);
	if (rc != 0) {
		SPDK_ERRLOG("getaddrinfo() failed (errno=%d)\n", errno);
		return NULL;
	}

	/* try listen */
	fd = -1;
	for (res = res0; res != NULL; res = res->ai_next) {
retry:
		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd < 0) {
			/* error */
			continue;
		}
		rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof val);
		if (rc != 0) {
			close(fd);
			/* error */
			continue;
		}
		rc = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof val);
		if (rc != 0) {
			close(fd);
			/* error */
			continue;
		}

		if (type == SPDK_SOCK_CREATE_LISTEN) {
			rc = bind(fd, res->ai_addr, res->ai_addrlen);
			if (rc != 0) {
				SPDK_ERRLOG("bind() failed, errno = %d\n", errno);
				switch (errno) {
				case EINTR:
					/* interrupted? */
					close(fd);
					goto retry;
				case EADDRNOTAVAIL:
					SPDK_ERRLOG("IP address %s not available. "
						    "Verify IP address in config file "
						    "and make sure setup script is "
						    "run before starting spdk app.\n", ip);
				/* FALLTHROUGH */
				default:
					/* try next family */
					close(fd);
					fd = -1;
					continue;
				}
			}
			/* bind OK */
			rc = listen(fd, 512);
			if (rc != 0) {
				SPDK_ERRLOG("listen() failed, errno = %d\n", errno);
				close(fd);
				fd = -1;
				break;
			}
		} else if (type == SPDK_SOCK_CREATE_CONNECT) {
			rc = connect(fd, res->ai_addr, res->ai_addrlen);
			if (rc != 0) {
				SPDK_ERRLOG("connect() failed, errno = %d\n", errno);
				/* try next family */
				close(fd);
				fd = -1;
				continue;
			}
		}

		flag = fcntl(fd, F_GETFL);
		if (fcntl(fd, F_SETFL, flag | O_NONBLOCK) < 0) {
			SPDK_ERRLOG("fcntl can't set nonblocking mode for socket, fd: %d (%d)\n", fd, errno);
			close(fd);
			fd = -1;
			break;
		}
		break;
	}
	freeaddrinfo(res0);

	if (fd < 0) {
		return NULL;
	}

	sock = calloc(1, sizeof(*sock));
	if (sock == NULL) {
		SPDK_ERRLOG("sock allocation failed\n");
		close(fd);
		return NULL;
	}

	sock->fd = fd;
	return sock;
}

static struct spdk_sock *
spdk_posix_sock_listen(const char *ip, int port)
{
	return spdk_posix_sock_create(ip, port, SPDK_SOCK_CREATE_LISTEN);
}

static struct spdk_sock *
spdk_posix_sock_connect(const char *ip, int port)
{
	return spdk_posix_sock_create(ip, port, SPDK_SOCK_CREATE_CONNECT);
}

static struct spdk_sock *
spdk_posix_sock_accept(struct spdk_sock *sock)
{
	struct sockaddr_storage		sa;
	socklen_t			salen;
	int				rc;
	struct spdk_sock		*new_sock;

	memset(&sa, 0, sizeof(sa));
	salen = sizeof(sa);

	assert(sock != NULL);

	rc = accept(sock->fd, (struct sockaddr *)&sa, &salen);

	if (rc == -1) {
		return NULL;
	}

	new_sock = calloc(1, sizeof(*sock));
	if (new_sock == NULL) {
		SPDK_ERRLOG("sock allocation failed\n");
		close(rc);
		return NULL;
	}

	new_sock->fd = rc;
	return new_sock;
}

static int
spdk_posix_sock_close(struct spdk_sock *sock)
{
	return close(sock->fd);
}

static ssize_t
spdk_posix_sock_recv(struct spdk_sock *sock, void *buf, size_t len)
{
	if (sock == NULL) {
		errno = EBADF;
		return -1;
	}

	return recv(sock->fd, buf, len, MSG_DONTWAIT);
}

static ssize_t
spdk_posix_sock_writev(struct spdk_sock *sock, struct iovec *iov, int iovcnt)
{
	if (sock == NULL) {
		errno = EBADF;
		return -1;
	}

	return writev(sock->fd, iov, iovcnt);
}

static int
spdk_posix_sock_set_recvlowat(struct spdk_sock *sock, int nbytes)
{
	int val;
	int rc;

	assert(sock != NULL);

	val = nbytes;
	rc = setsockopt(sock->fd, SOL_SOCKET, SO_RCVLOWAT, &val, sizeof val);
	if (rc != 0) {
		return -1;
	}
	return 0;
}

static int
spdk_posix_sock_set_recvbuf(struct spdk_sock *sock, int sz)
{
	assert(sock != NULL);

	return setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF,
			  &sz, sizeof(sz));
}

static int
spdk_posix_sock_set_sendbuf(struct spdk_sock *sock, int sz)
{
	assert(sock != NULL);

	return setsockopt(sock->fd, SOL_SOCKET, SO_SNDBUF,
			  &sz, sizeof(sz));
}

static bool
spdk_posix_sock_is_ipv6(struct spdk_sock *sock)
{
	struct sockaddr_storage sa;
	socklen_t salen;
	int rc;

	assert(sock != NULL);

	memset(&sa, 0, sizeof sa);
	salen = sizeof sa;
	rc = getsockname(sock->fd, (struct sockaddr *) &sa, &salen);
	if (rc != 0) {
		SPDK_ERRLOG("getsockname() failed (errno=%d)\n", errno);
		return false;
	}

	return (sa.ss_family == AF_INET6);
}

static bool
spdk_posix_sock_is_ipv4(struct spdk_sock *sock)
{
	struct sockaddr_storage sa;
	socklen_t salen;
	int rc;

	assert(sock != NULL);

	memset(&sa, 0, sizeof sa);
	salen = sizeof sa;
	rc = getsockname(sock->fd, (struct sockaddr *) &sa, &salen);
	if (rc != 0) {
		SPDK_ERRLOG("getsockname() failed (errno=%d)\n", errno);
		return false;
	}

	return (sa.ss_family == AF_INET);
}

static struct spdk_sock_group *
spdk_posix_sock_group_create(void)
{
	struct spdk_sock_group *sock_group;
	int fd;

#if defined(__linux__)
	fd = epoll_create1(0);
#elif defined(__FreeBSD__)
	fd = kqueue();
#endif
	if (fd == -1) {
		return NULL;
	}

	sock_group = calloc(1, sizeof(*sock_group));
	if (sock_group == NULL) {
		SPDK_ERRLOG("sock_group allocation failed\n");
		close(fd);
		return NULL;
	}

	sock_group->fd = fd;
	TAILQ_INIT(&sock_group->socks);

	return sock_group;
}

static int
spdk_posix_sock_group_add_sock(struct spdk_sock_group *group, struct spdk_sock *sock,
			       spdk_sock_cb cb_fn, void *cb_arg)
{
	int rc;

	if (cb_fn == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (sock->cb_fn != NULL) {
		/*
		 * This sock is already part of a sock_group.  Currently we don't
		 *  support this.
		 */
		errno = EBUSY;
		return -1;
	}

#if defined(__linux__)
	struct epoll_event event;

	event.events = EPOLLIN;
	event.data.ptr = sock;

	rc = epoll_ctl(group->fd, EPOLL_CTL_ADD, sock->fd, &event);
#elif defined(__FreeBSD__)
	struct kevent event;
	struct timespec ts = {0};

	EV_SET(&event, sock->fd, EVFILT_READ, EV_ADD, 0, 0, sock);

	rc = kevent(group->fd, &event, 1, NULL, 0, &ts);
#endif
	if (rc == 0) {
		TAILQ_INSERT_TAIL(&group->socks, sock, link);
		sock->cb_fn = cb_fn;
		sock->cb_arg = cb_arg;
	}

	return rc;
}

static int
spdk_posix_sock_group_remove_sock(struct spdk_sock_group *group, struct spdk_sock *sock)
{
	int rc;
#if defined(__linux__)
	struct epoll_event event;

	/* Event parameter is ignored but some old kernel version still require it. */
	rc = epoll_ctl(group->fd, EPOLL_CTL_DEL, sock->fd, &event);
#elif defined(__FreeBSD__)
	struct kevent event;
	struct timespec ts = {0};

	EV_SET(&event, sock->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);

	rc = kevent(group->fd, &event, 1, NULL, 0, &ts);
	if (rc == 0 && event.flags & EV_ERROR) {
		rc = -1;
		errno = event.data;
	}
#endif
	if (rc == 0) {
		TAILQ_REMOVE(&group->socks, sock, link);
		sock->cb_fn = NULL;
		sock->cb_arg = NULL;
	}

	return rc;
}

static int
spdk_posix_sock_group_poll_count(struct spdk_sock_group *group, int max_events)
{
	struct spdk_sock *sock;
	int num_events, i;

	if (max_events < 1) {
		errno = -EINVAL;
		return -1;
	}

	/*
	 * Only poll for up to 32 events at a time - if more events are pending,
	 *  the next call to this function will reap them.
	 */
	if (max_events > MAX_EVENTS_PER_POLL) {
		max_events = MAX_EVENTS_PER_POLL;
	}

#if defined(__linux__)
	struct epoll_event events[MAX_EVENTS_PER_POLL];

	num_events = epoll_wait(group->fd, events, max_events, 0);
#elif defined(__FreeBSD__)
	struct kevent events[MAX_EVENTS_PER_POLL];
	struct timespec ts = {0};

	num_events = kevent(group->fd, NULL, 0, events, max_events, &ts);
#endif

	if (num_events == -1) {
		return -1;
	}

	for (i = 0; i < num_events; i++) {
#if defined(__linux__)
		sock = events[i].data.ptr;
#elif defined(__FreeBSD__)
		sock = events[i].udata;
#endif

		assert(sock->cb_fn != NULL);
		sock->cb_fn(sock->cb_arg, group, sock);
	}

	return 0;
}

static int
spdk_posix_sock_group_close(struct spdk_sock_group *group)
{
	return close(group->fd);
}

int
spdk_sock_getaddr(struct spdk_sock *sock, char *saddr, int slen, char *caddr, int clen)
{
	return spdk_posix_sock_getaddr(sock, saddr, slen, caddr, clen);
}

struct spdk_sock *
spdk_sock_connect(const char *ip, int port)
{
	return spdk_posix_sock_connect(ip, port);
}

struct spdk_sock *
spdk_sock_listen(const char *ip, int port)
{
	return spdk_posix_sock_listen(ip, port);
}

struct spdk_sock *
spdk_sock_accept(struct spdk_sock *sock)
{
	return spdk_posix_sock_accept(sock);
}

int
spdk_sock_close(struct spdk_sock **sock)
{
	int rc;

	if (*sock == NULL) {
		errno = EBADF;
		return -1;
	}

	if ((*sock)->cb_fn != NULL) {
		/* This sock is still part of a sock_group. */
		errno = EBUSY;
		return -1;
	}

	rc = spdk_posix_sock_close(*sock);
	if (rc == 0) {
		free(*sock);
		*sock = NULL;
	}

	return rc;
}

ssize_t
spdk_sock_recv(struct spdk_sock *sock, void *buf, size_t len)
{
	return spdk_posix_sock_recv(sock, buf, len);
}

ssize_t
spdk_sock_writev(struct spdk_sock *sock, struct iovec *iov, int iovcnt)
{
	return spdk_posix_sock_writev(sock, iov, iovcnt);
}


int
spdk_sock_set_recvlowat(struct spdk_sock *sock, int nbytes)
{
	return spdk_posix_sock_set_recvlowat(sock, nbytes);
}

int
spdk_sock_set_recvbuf(struct spdk_sock *sock, int sz)
{
	return spdk_posix_sock_set_recvbuf(sock, sz);
}

int
spdk_sock_set_sendbuf(struct spdk_sock *sock, int sz)
{
	return spdk_posix_sock_set_sendbuf(sock, sz);
}

bool
spdk_sock_is_ipv6(struct spdk_sock *sock)
{
	return spdk_posix_sock_is_ipv6(sock);
}

bool
spdk_sock_is_ipv4(struct spdk_sock *sock)
{
	return spdk_posix_sock_is_ipv4(sock);
}

struct spdk_sock_group *
spdk_sock_group_create(void)
{
	return spdk_posix_sock_group_create();
}

int
spdk_sock_group_add_sock(struct spdk_sock_group *group, struct spdk_sock *sock,
			 spdk_sock_cb cb_fn, void *cb_arg)
{
	return spdk_posix_sock_group_add_sock(group, sock, cb_fn, cb_arg);
}

int
spdk_sock_group_remove_sock(struct spdk_sock_group *group, struct spdk_sock *sock)
{
	return spdk_posix_sock_group_remove_sock(group, sock);
}

int
spdk_sock_group_poll(struct spdk_sock_group *group)
{
	return spdk_sock_group_poll_count(group, MAX_EVENTS_PER_POLL);
}

int
spdk_sock_group_poll_count(struct spdk_sock_group *group, int max_events)
{
	return spdk_posix_sock_group_poll_count(group, max_events);
}

int
spdk_sock_group_close(struct spdk_sock_group **group)
{
	int rc;

	if (*group == NULL) {
		errno = EBADF;
		return -1;
	}

	if (!TAILQ_EMPTY(&(*group)->socks)) {
		errno = EBUSY;
		return -1;
	}

	rc = spdk_posix_sock_group_close(*group);
	if (rc == 0) {
		free(*group);
		*group = NULL;
	}

	return rc;
}
