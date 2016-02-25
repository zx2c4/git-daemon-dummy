/*
 * git-daemon-dummy.c
 * 
 * Instructs users to use an https:// clone/pull/push URI instead of git://
 *
 * Copyright 2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * This file is licensed under the GPLv3. Please see COPYING for more information.
 *
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include "seccomp-bpf.h"

enum {
	LISTEN_BACKLOG = 16,
	EPOLL_EVENTS = 128,
	MAX_MSG_SIZE = 1024
};

static void drop_privileges(void)
{
	struct passwd *user;
	struct rlimit limit;
	
	if (!geteuid()) {
		user = getpwnam("nobody");
		if (!user) {
			perror("getpwnam");
			exit(EXIT_FAILURE);
		}
		if (chroot("/var/empty")) {
			perror("chroot");
			exit(EXIT_FAILURE);
		}
		if (chdir("/")) {
			perror("chdir");
			exit(EXIT_FAILURE);
		}
		if (setresgid(user->pw_gid, user->pw_gid, user->pw_gid)) {
			perror("setresgid");
			exit(EXIT_FAILURE);
		}
		if (setgroups(1, &user->pw_gid)) {
			perror("setgroups");
			exit(EXIT_FAILURE);
		}
		if (setresuid(user->pw_uid, user->pw_uid, user->pw_uid)) {
			perror("setresuid");
			exit(EXIT_FAILURE);
		}
	}
	limit.rlim_cur = limit.rlim_max = 4194304 /* 4 megs */;
	setrlimit(RLIMIT_DATA, &limit);
	setrlimit(RLIMIT_FSIZE, &limit);
	setrlimit(RLIMIT_MEMLOCK, &limit);
	setrlimit(RLIMIT_STACK, &limit);
	limit.rlim_cur = limit.rlim_max = 15728640 /* 15 megabytes */;
	setrlimit(RLIMIT_AS, &limit);
	limit.rlim_cur = limit.rlim_max = 0;
	setrlimit(RLIMIT_CORE, &limit);
	setrlimit(RLIMIT_NPROC, &limit);

	if (!geteuid() || !getegid()) {
		fprintf(stderr, "Error: unable to drop privileges.\n");
		exit(EXIT_FAILURE);
	}

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(NO_NEW_PRIVS)");
		exit(EXIT_FAILURE);
	}

	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) {
		perror("prctl(PR_SET_DUMPABLE)");
		exit(EXIT_FAILURE);
	}
}


void seccomp_enable_filter(void)
{
	struct sock_filter filter[] = {
		VALIDATE_ARCHITECTURE,
		EXAMINE_SYSCALL,
		ALLOW_SYSCALL(exit_group),
		ALLOW_SYSCALL(exit),
		ALLOW_SYSCALL(read),
		ALLOW_SYSCALL(write),
		ALLOW_SYSCALL(epoll_wait),
		ALLOW_SYSCALL(epoll_pwait),
		ALLOW_SYSCALL(epoll_ctl),
		ALLOW_SYSCALL(accept4),
		ALLOW_SYSCALL(close),
		ALLOW_SYSCALL(mmap),
		ALLOW_SYSCALL(brk),
		KILL_PROCESS
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter
	};
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		perror("prctl(SECCOMP)");
		exit(EXIT_FAILURE);
	}
}

static void parse_options(int argc, char *argv[], bool *daemonize, int *port, char **pid_file)
{
	static const struct option long_options[] = {
		{"daemonize", no_argument, NULL, 'd'},
		{"foreground", no_argument, NULL, 'f'},
		{"port", required_argument, NULL, 'p'},
		{"pid-file", required_argument, NULL, 'P'},
		{"help", no_argument, NULL, 'h'},
		{0, 0, 0, 0}
	};
	int option_index = 0, option;

	*pid_file = NULL;
	*daemonize = false;
	*port = 9418;

	while ((option = getopt_long(argc, argv, "dfP:p:h", long_options, &option_index)) != -1) {
		switch (option) {
			case 'd':
				*daemonize = true;
				break;
			case 'f':
				*daemonize = false;
				break;
			case 'p':
				*port = atoi(optarg);
				break;
			case 'P':
				*pid_file = optarg;
				break;
			case 'h':
			case '?':
			default:
				fprintf(stderr, "Usage: %s [OPTION]...\n", argv[0]);
				fprintf(stderr, "  -d, --daemonize              run as a background daemon\n");
				fprintf(stderr, "  -f, --foreground             run in the foreground (default)\n");
				fprintf(stderr, "  -P FILE, --pid-file=FILE     write pid of listener process to FILE\n");
				fprintf(stderr, "  -p PORT, --port=PORT         listen on port PORT (default=9418)\n");
				fprintf(stderr, "  -h, --help                   display this message\n");
				exit(option == 'h' ? EXIT_SUCCESS : EXIT_FAILURE);
		}
	}
}

static int get_listen_socket(int port)
{
	int flag, fd;
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = in6addr_any,
		.sin6_port = htons(port)
	};

	fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	flag = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
	flag = 0;
	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag));

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}
	if (listen(fd, LISTEN_BACKLOG) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}
	return fd;
}

static void daemonize_and_pidfile(bool daemonize, const char *pid_file)
{
	FILE *pidfile;

	if (pid_file) {
		pidfile = fopen(pid_file, "w");
		if (!pidfile) {
			perror("fopen");
			exit(EXIT_FAILURE);
		}
	}
	if (daemonize) {
		if (daemon(0, 1) < 0) {
			perror("daemon");
			exit(EXIT_FAILURE);
		}
	}
	if (pid_file) {
		if (fprintf(pidfile, "%d\n", getpid()) < 0) {
			perror("fprintf");
			exit(EXIT_FAILURE);
		}
		fclose(pidfile);
	}
}

static int setup_epoll(int listen_fd)
{
	int epoll_fd;
	struct epoll_event event = {
		.events = EPOLLIN | EPOLLET,
		.data = {
			.fd = listen_fd
		}
	};

	epoll_fd = epoll_create1(0);
	if (epoll_fd == -1) {
		perror("epoll_create1");
		exit(EXIT_FAILURE);
	}

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &event) < 0) {
		perror("epoll_ctl");
		exit(EXIT_FAILURE);
	}

	return epoll_fd;
}

static void process_request(int epoll_fd, int fd, bool direct);
struct out_data {
	int fd;
	unsigned int len;
	char data[];
};

static void event_new_connection(int epoll_fd, struct epoll_event *event)
{
	int connection_fd;

	if (event->events & EPOLLERR || event->events & EPOLLHUP)
		exit(EXIT_FAILURE);

	for (;;) {
		connection_fd = accept4(event->data.fd, NULL, NULL, SOCK_NONBLOCK);
		if (connection_fd < 0)
			break;
		process_request(epoll_fd, connection_fd, true);
	}
}

static void event_can_read(int epoll_fd, struct epoll_event *event)
{
	if (event->events & EPOLLERR || event->events & EPOLLHUP)
		close(event->data.fd);
	else
		process_request(epoll_fd, event->data.fd, false);
}

static void event_can_write(int epoll_fd, struct epoll_event *event)
{
	struct out_data *out = event->data.ptr;
	if (event->events & EPOLLERR || event->events & EPOLLHUP) {
		close(out->fd);
		free(out);
		return;
	}
	if (write(out->fd, out->data, out->len) != out->len) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			close(out->fd);
			free(out);
		}
		return;
	}
	close(out->fd);
}

static void event_loop(int epoll_fd, int listen_fd)
{
	struct epoll_event events[EPOLL_EVENTS] = { 0 };
	int num_events;

	while ((num_events = epoll_wait(epoll_fd, events, EPOLL_EVENTS, -1)) >= 0) {
		for (int i = 0; i < num_events; ++i) {
			if (events[i].data.fd == listen_fd)
				event_new_connection(epoll_fd, &events[i]);
			else if (events[i].events & EPOLLIN)
				event_can_read(epoll_fd, &events[i]);
			else if (events[i].events & EPOLLOUT)
				event_can_write(epoll_fd, &events[i]);
		}
	}
}


static int parse_data(int fd, char *buf, char **repo, char **host)
{
	size_t line_len, parsed_len;
	ssize_t len;

	if (read(fd, buf, 4) != 4)
		return (errno == EAGAIN || errno == EWOULDBLOCK) ? -2 : -1;

	buf[4] = '\0';
	parsed_len = strtoul(buf, NULL, 16);
	if (parsed_len <= 4)
		return -1;
	parsed_len -= 4;
	if (parsed_len >= MAX_MSG_SIZE)
		return -1;

	len = read(fd, buf, parsed_len);
	if (len != parsed_len)
		return -1;
	buf[len] = '\0';

	line_len = strlen(buf);
	if (line_len && buf[line_len - 1] == '\n')
		buf[--line_len] = '\0';

	if (len <= line_len)
		return -1;

	*repo = buf;
	if (strncasecmp(*repo, "git-upload-pack ", strlen("git-upload-pack ")))
		return -1;
	*repo += strlen("git-upload-pack ");
	if (*repo[0] != '/') {
		--*repo;
		*repo[0] = '/';
	}

	*host = buf + line_len + 1;
	if (strncasecmp(*host, "host=", strlen("host=")))
		return -1;
	*host += strlen("host=");
	if (!*host[0])
		return -1;

	return 0;
}

static void process_request(int epoll_fd, int fd, bool direct)
{
	static const char message_template[] = "\n******************************************************\n\n  This git repository has moved! Please clone with:\n\n      $ git clone https://%s%s\n\n******************************************************";
	char buf[MAX_MSG_SIZE];
	struct out_data *out, *copy = NULL;
	size_t msg_len, buffer_len;
	char *repo, *host;
	int ret;

	ret = parse_data(fd, buf, &repo, &host);
	if (ret == -1)
		goto err;
	else if (ret == -2) {
		struct epoll_event new_event = {
			.events = EPOLLIN | EPOLLET,
			.data = {
				.fd = fd
			}
		};
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &new_event) < 0)
			goto err;
		return;
	}

	msg_len = strlen(repo) + strlen(host) + strlen(message_template) - 2 + 1;
	buffer_len = msg_len + sizeof(struct out_data);
	if (buffer_len > MAX_MSG_SIZE * 2)
		goto err;
	out = alloca(buffer_len);
	out->fd = fd;
	out->len = 8 + msg_len;
	if (out->len > 0xffff)
		goto err;
	sprintf(out->data, "%04x", out->len);
	memcpy(out->data + 4, "ERR ", 4);
	sprintf(out->data + 8, message_template, host, repo);

	if (write(fd, out->data, out->len) != out->len) {
		struct epoll_event new_event = {
			.events = EPOLLOUT
		};
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			goto err;
		copy = malloc(buffer_len);
		if (!copy)
			goto err;
		memcpy(copy, out, buffer_len);
		new_event.data.ptr = copy;
		if (epoll_ctl(epoll_fd, direct ? EPOLL_CTL_ADD : EPOLL_CTL_MOD, fd, &new_event) < 0)
			goto err;
		return;
	}
err:
	close(fd);
	free(copy);
}

int main(int argc, char *argv[])
{
	int listen_fd, epoll_fd, port;
	bool daemonize;
	char *pid_file;

	close(STDIN_FILENO);
	parse_options(argc, argv, &daemonize, &port, &pid_file);
	listen_fd = get_listen_socket(port);
	epoll_fd = setup_epoll(listen_fd);
	daemonize_and_pidfile(daemonize, pid_file);
	prctl(PR_SET_NAME, "git-daemon-dummy");
	drop_privileges();
	seccomp_enable_filter();
	event_loop(epoll_fd, listen_fd);
	return EXIT_FAILURE;
}
