/*
 * git-daemon-dummy.c
 * 
 * Instructs users to use an https:// clone/pull/push URI instead of git://
 *
 * Copyright 2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
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

static const char MESSAGE_TEMPLATE[] = "\n******************************************************\n\n  This git repository has moved! Please clone with:\n\n      $ git clone %s%s\n\n******************************************************";

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

static void parse_options(int argc, char *argv[], bool *daemonize, int *port, char **pid_file, char **message)
{
	static const struct option long_options[] = {
		{"uri-prefix", required_argument, NULL, 'u'},
		{"daemonize", no_argument, NULL, 'd'},
		{"foreground", no_argument, NULL, 'f'},
		{"port", required_argument, NULL, 'p'},
		{"pid-file", required_argument, NULL, 'P'},
		{"help", no_argument, NULL, 'h'},
		{0, 0, 0, 0}
	};
	int option_index = 0, option;

	*message = NULL;
	*pid_file = NULL;
	*daemonize = false;
	*port = 9418;

	while ((option = getopt_long(argc, argv, "u:dfP:p:h", long_options, &option_index)) != -1) {
		switch (option) {
			case 'u': {
				size_t len = strlen(optarg);
				if (len && optarg[len - 1] == '/')
					optarg[len - 1] = '\0';
				if (asprintf(message, MESSAGE_TEMPLATE, optarg, "%s") < 0) {
					perror("asprintf");
					exit(EXIT_FAILURE);
				}
				break;
			}
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
				fprintf(stderr, "  -u URI, --uri-prefix=URI     use URI as prefix to redirect uri (default=https://git.example.com)\n");
				fprintf(stderr, "  -d, --daemonize              run as a background daemon\n");
				fprintf(stderr, "  -f, --foreground             run in the foreground (default)\n");
				fprintf(stderr, "  -P FILE, --pid-file=FILE     write pid of listener process to FILE\n");
				fprintf(stderr, "  -p PORT, --port=PORT         listen on port PORT (default=9418)\n");
				fprintf(stderr, "  -h, --help                   display this message\n");
				exit(option == 'h' ? EXIT_SUCCESS : EXIT_FAILURE);
		}
	}

	if (!*message) {
		if (asprintf(message, MESSAGE_TEMPLATE, "https://git.example.com", "%s") < 0) {
			perror("asprintf");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "Warning: please specify -u/--uri-prefix to avoid returning the example prefix.\n");
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

static void handle_new_connection(int epoll_fd, struct epoll_event *event)
{
	int connection_fd;
	struct epoll_event new_event = {
		.events = EPOLLIN | EPOLLET
	};

	if (event->events & EPOLLERR || event->events & EPOLLHUP)
		exit(EXIT_FAILURE);

	for (;;) {
		connection_fd = accept4(event->data.fd, NULL, NULL, SOCK_NONBLOCK);
		if (connection_fd < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			perror("accept4");
			break;
		}
		new_event.data.fd = connection_fd;
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, connection_fd, &new_event) < 0) {
			perror("epoll_ctl");
			close(connection_fd);
		}
	}
}

struct out_data {
	int fd;
	char repo[];
};

static void handle_read_data(int epoll_fd, struct epoll_event *event)
{
	struct out_data *out;
	char buf[MAX_MSG_SIZE];
	char *repo;
	ssize_t len;
	unsigned long total_size;
	struct epoll_event new_event = {
		.events = EPOLLOUT
	};

	if (read(event->data.fd, buf, 4) != 4) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			close(event->data.fd);
		return;
	}
	buf[4] = '\0';
	total_size = strtoul(buf, NULL, 16);
	if (total_size <= 4 || total_size > MAX_MSG_SIZE) {
		close(event->data.fd);
		return;
	}

	len = read(event->data.fd, buf, total_size - 4);
	if (len != total_size - 4) {
		close(event->data.fd);
		return;
	}
	if (buf[len - 1]) {
		close(event->data.fd);
		return;
	}
	if (strncmp(buf, "git-upload-pack ", strlen("git-upload-pack "))) {
		close(event->data.fd);
		return;
	}

	repo = buf + strlen("git-upload-pack ");
	if (repo[0] != '/') {
		--repo;
		repo[0] = '/';
	}
	out = malloc(sizeof(struct out_data) + strlen(repo) + 1);
	if (!out) {
		close(event->data.fd);
		return;
	}
	out->fd = event->data.fd;
	strcpy(out->repo, repo);
	new_event.data.ptr = out;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, out->fd, &new_event) < 0) {
		free(out);
		close(event->data.fd);
	}
}

static void handle_write_data(int epoll_fd, const char *message, struct epoll_event *event)
{
	struct out_data *out = event->data.ptr;
	char hexlen[128];
	size_t msg_len = strlen(out->repo) + strlen(message) - 2 + 1;
	unsigned int len = 8 + msg_len;
	struct {
		char len[4];
		char err[4];
		char message[msg_len];
	} __attribute__((packed)) to_send;

	sprintf(hexlen, "%04x", len);
	memcpy(to_send.len, hexlen, 4);
	memcpy(to_send.err, "ERR ", 4);
	sprintf(to_send.message, message, out->repo);

	if (write(out->fd, (void *)&to_send, len) < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		return;

	close(out->fd);
	free(out);
}

static void handle_new_data(int epoll_fd, const char *message, struct epoll_event *event)
{
	if (event->events & EPOLLERR || event->events & EPOLLHUP || !(event->events & EPOLLIN || event->events & EPOLLOUT)) {
		close(event->data.fd);
		return;
	}
	if (event->events & EPOLLIN)
		handle_read_data(epoll_fd, event);
	if (event->events & EPOLLOUT)
		handle_write_data(epoll_fd, message, event);
}

static void event_loop(int epoll_fd, int listen_fd, const char *message)
{
	struct epoll_event events[EPOLL_EVENTS] = { 0 };
	int num_events;

	while ((num_events = epoll_wait(epoll_fd, events, EPOLL_EVENTS, -1)) >= 0) {
		for (int i = 0; i < num_events; ++i) {
			if (events[i].data.fd == listen_fd)
				handle_new_connection(epoll_fd, &events[i]);
			else
				handle_new_data(epoll_fd, message, &events[i]);
		}
	}

	perror("epoll_wait");
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int listen_fd, epoll_fd, port;
	bool daemonize;
	char *message, *pid_file;

	close(STDIN_FILENO);
	parse_options(argc, argv, &daemonize, &port, &pid_file, &message);
	listen_fd = get_listen_socket(port);
	epoll_fd = setup_epoll(listen_fd);
	daemonize_and_pidfile(daemonize, pid_file);
	prctl(PR_SET_NAME, "git-daemon-dummy");
	drop_privileges();
	seccomp_enable_filter();
	event_loop(epoll_fd, listen_fd, message);
	return EXIT_FAILURE;
}
