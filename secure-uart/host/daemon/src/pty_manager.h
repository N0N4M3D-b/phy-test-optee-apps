/* SPDX-License-Identifier: MIT */
#ifndef PTY_MANAGER_H
#define PTY_MANAGER_H

#include <stddef.h>
#include <sys/types.h>

int pty_spawn_shell(int *master_fd, pid_t *shell_pid);
ssize_t pty_read(int master_fd, void *buffer, size_t length);
ssize_t pty_write(int master_fd, const void *buffer, size_t length);
void pty_cleanup(int master_fd, pid_t shell_pid);

#endif /* PTY_MANAGER_H */
