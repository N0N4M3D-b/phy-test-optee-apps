/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <pty.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#include "pty_manager.h"

int pty_spawn_shell(int *master_fd, pid_t *shell_pid)
{
	pid_t pid;

	if (!master_fd || !shell_pid) {
		errno = EINVAL;
		return -1;
	}

	pid = forkpty(master_fd, NULL, NULL, NULL);
	if (pid < 0)
		return -1;
	if (!pid) {
		setenv("TERM", "vt100", 1);
		execl("/bin/sh", "sh", "-i", NULL);
		_exit(127);
	}

	*shell_pid = pid;
	return 0;
}

ssize_t pty_read(int master_fd, void *buffer, size_t length)
{
	ssize_t count;

	do {
		count = read(master_fd, buffer, length);
	} while (count < 0 && errno == EINTR);
	return count;
}

ssize_t pty_write(int master_fd, const void *buffer, size_t length)
{
	const char *cursor = buffer;
	size_t offset = 0;

	while (offset < length) {
		ssize_t count = write(master_fd, cursor + offset, length - offset);

		if (count < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		offset += count;
	}
	return offset;
}

void pty_cleanup(int master_fd, pid_t shell_pid)
{
	if (master_fd >= 0)
		close(master_fd);
	if (shell_pid > 0) {
		kill(shell_pid, SIGTERM);
		while (waitpid(shell_pid, NULL, 0) < 0 && errno == EINTR)
			;
	}
}
