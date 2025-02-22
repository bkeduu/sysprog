#include "parser.h"
#include "rlist.h"

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

#define container_of(ptr, type, member) (type*)((char*)(ptr) - offsetof(type, member))

struct chain_command {
	const struct expr *expression;
	struct rlist link;
};

struct exec_result {
	int need_exit;
	int return_code;
};

static struct exec_result
make_result(int need_exit, int return_code)
{
	struct exec_result res;
	res.need_exit = need_exit;
	res.return_code = return_code;
	return res;
}

static int
handle_cd_command(const struct expr *expression)
{
	assert(expression != NULL);

	if (expression->cmd.arg_count != 1) {
		return 1;
	}

	const char *target_path = expression->cmd.args[0];
	if (target_path == NULL) {
		return 1;
	}

	return chdir(target_path);
}

static void
execute_cmd(const struct expr *expression)
{
	assert(expression != NULL);

	char **args = calloc(expression->cmd.arg_count + 2, sizeof(char *));
	args[0] = expression->cmd.exe;
	memcpy(args + 1, expression->cmd.args, sizeof(char *) * expression->cmd.arg_count);
	execvp(expression->cmd.exe, args);
}

static void
free_cmd_rlist(struct rlist *head)
{
	assert(head != NULL);

	struct rlist *cmd_iter = rlist_next(head);
	while (cmd_iter != head) {
		struct rlist *next_cmd = rlist_next(cmd_iter);
		rlist_del(cmd_iter);
		struct chain_command *cc = container_of(cmd_iter, struct chain_command, link);
		free(cc);
		cmd_iter = next_cmd;
	}
}

static int
wait_children_and_free(pid_t *children, size_t children_count)
{
	assert(children != NULL);

	int last_exitcode = 0;

	for (size_t child_idx = 0; child_idx < children_count; ++child_idx) {
		int status;
		waitpid(children[child_idx], &status, 0);

		if (WIFEXITED(status)) {
			last_exitcode = WEXITSTATUS(status);
		}
	}
	free(children);

	return last_exitcode;
}

static void
close_pipes(int *pipes_fds, size_t size)
{
	assert(pipes_fds != NULL);

	for (size_t fd_idx = 0; fd_idx < size; ++fd_idx) {
		close(pipes_fds[fd_idx]);
	}
}

static struct exec_result
execute_logical_operand(struct rlist *cmd_list_head, size_t cmd_count,
	const char *out_file, enum output_type out_type, int need_wait)
{
	assert(cmd_list_head != NULL);

	size_t child_size = 0;
	pid_t *children_pids = NULL;
	if (need_wait) {
		children_pids = calloc(cmd_count, sizeof(pid_t));
		if (children_pids == NULL) {
			puts("calloc error\n");
			free_cmd_rlist(cmd_list_head);
			return make_result(0, 1);
		}
	}

	int *pipes_fds = calloc(2 * cmd_count, sizeof(int));
	if (pipes_fds == NULL) {
		puts("calloc error\n");
		free_cmd_rlist(cmd_list_head);
		free(children_pids);
		return make_result(0, 1);
	}

	for (size_t i = 0; i < cmd_count - 1; ++i) {
		if (pipe(pipes_fds + 2 * i + 1) != 0) {
			puts("pipe creation error\n");

			free_cmd_rlist(cmd_list_head);
			close_pipes(pipes_fds + 1, i);
			free(pipes_fds);
			free(children_pids);

			return make_result(0, 1);
		}

		int tmp = pipes_fds[2 * i + 1];
		pipes_fds[2 * i + 1] = pipes_fds[2 * (i + 1)];
		pipes_fds[2 * (i + 1)] = tmp;
	}

	pipes_fds[0] = STDIN_FILENO;
	pipes_fds[2 * cmd_count - 1] = STDOUT_FILENO;

	size_t i = 0;
	struct rlist *cmd_iter;

	rlist_foreach(cmd_iter, cmd_list_head) {
		struct chain_command *cc = container_of(cmd_iter, struct chain_command, link);
		const struct expr *expression = cc->expression;

		if (strcmp("cd", expression->cmd.exe) == 0) {
			if (cmd_count == 1 && handle_cd_command(expression) != 0) {
				puts("cd error\n");

				free_cmd_rlist(cmd_list_head);
				close_pipes(pipes_fds, 2 * (cmd_count - 1));
				free(pipes_fds);
				free(children_pids);

				return make_result(0, -1);
			}
		}
		else if (strcmp("exit", expression->cmd.exe) == 0) {
			if (i == cmd_count - 1) {
				free_cmd_rlist(cmd_list_head);
				close_pipes(pipes_fds + 1, 2 * (cmd_count - 1));
				free(pipes_fds);
				wait_children_and_free(children_pids, child_size);

				if (expression->cmd.arg_count != 0) {
					char *end;
					int return_code = (int) strtol(expression->cmd.args[0], &end, 10);
					return make_result(cmd_count == 1, return_code);
				}

				return make_result(cmd_count == 1, 0);
			}
		}
		else {
			pid_t child_pid = fork();
			switch (child_pid) {
				case -1: {
					puts("fork error\n");
					free_cmd_rlist(cmd_list_head);
					close_pipes(pipes_fds + 1, 2 * (cmd_count - 1));
					free(pipes_fds);
					wait_children_and_free(children_pids, child_size);

					return make_result(1, 1);
				}

				case 0: {
					free(children_pids);

					for (size_t fd_idx = 1; fd_idx < 2 * cmd_count - 1; ++fd_idx) {
						if (fd_idx != 2 * i + 1 && fd_idx != 2 * i) {
							close(pipes_fds[fd_idx]);
						}
					}

					if (need_wait != 0 || i != 0) {
						if (dup2(pipes_fds[2 * i], STDIN_FILENO) != STDIN_FILENO) {
							puts("dup2 error\n");

							close(pipes_fds[2 * i]);
							close(pipes_fds[2 * i + 1]);
							free(pipes_fds);

							return make_result(1, 0);
						}
					}
					else {
						close(STDIN_FILENO);
					}

					int out_fd = pipes_fds[2 * i + 1];
					if (out_type != OUTPUT_TYPE_STDOUT && out_file != NULL && i == cmd_count - 1) {
						out_fd = open(out_file,
							O_CREAT | O_WRONLY | (out_type == OUTPUT_TYPE_FILE_NEW ? O_TRUNC : O_APPEND),
							S_IRWXU | S_IRWXG | S_IRWXO
						);
						if (out_fd == -1) {
							puts("out file open error\n");

							close(pipes_fds[2 * i]);
							close(pipes_fds[2 * i + 1]);
							free(pipes_fds);

							return make_result(1, 0);
						}
					}

					if (dup2(out_fd, STDOUT_FILENO) != STDOUT_FILENO) {
						puts("dup2 error\n");

						close(pipes_fds[2 * i]);
						close(pipes_fds[2 * i + 1]);
						free(pipes_fds);

						return make_result(1, 0);
					}

					free(pipes_fds);

					execute_cmd(expression);
					return make_result(1, 0);
				}

				default: {
					if (need_wait) {
						children_pids[child_size++] = child_pid;
					}
					break;
				}
			}
		}

		++i;
	}

	free_cmd_rlist(cmd_list_head);
	close_pipes(pipes_fds + 1, 2 * (cmd_count - 1));
	free(pipes_fds);

	if (need_wait) {
		return make_result(0, wait_children_and_free(children_pids, child_size));
	}

	return make_result(0, 0);
}

static struct exec_result
execute_command_line(const struct command_line *line)
{
	assert(line != NULL);

	struct expr *iter = line->head;
	struct exec_result line_result = make_result(0, 0);

	while (iter != NULL) {
		size_t cmd_count = 0;
		enum expr_type logical_op_found = 0;
		struct rlist operand_cmd_list;
		rlist_create(&operand_cmd_list);

		while (iter != NULL && (logical_op_found != EXPR_TYPE_AND && logical_op_found != EXPR_TYPE_OR)) {
			switch (iter->type) {
			case EXPR_TYPE_COMMAND: {
				struct chain_command *cc = calloc(1, sizeof(struct chain_command));
				if (cc == NULL) {
					puts("calloc error\n");
					free_cmd_rlist(&operand_cmd_list);
					return make_result(0, 0);
				}

				cc->expression = iter;
				rlist_add_tail(&operand_cmd_list, &cc->link);
				++cmd_count;
				iter = iter->next;
				break;
			}

			case EXPR_TYPE_AND:
			case EXPR_TYPE_OR: {
				logical_op_found = iter->type;
				break;
			}

			default: {
				iter = iter->next;
				break;
			}
			}
		}

		struct exec_result res = execute_logical_operand(&operand_cmd_list, cmd_count,
			iter == NULL ? line->out_file : NULL, line->out_type, iter == NULL ? (line->is_background == 0) : 1);

		if (res.need_exit) {
			return res;
		}

		switch (logical_op_found) {
		case EXPR_TYPE_AND: {
			if (res.return_code != 0) {
				return res;
			}

			line_result = res;
			iter = iter->next;
			break;
		}

		case EXPR_TYPE_OR: {
			if (res.return_code == 0) {
				return res;
			}

			line_result = res;
			iter = iter->next;
			break;
		}

		default: {
			return res;
			break;
		}
		}
	}

	return line_result;
}

int
main(void)
{
	const size_t buf_size = 1024;
	char buf[buf_size];
	ssize_t rc;
	struct parser *p = parser_new();
	int last_retcode = 0;

	while ((rc = read(STDIN_FILENO, buf, buf_size)) > 0) {
		parser_feed(p, buf, rc);
		struct command_line *line = NULL;
		while (true) {
			enum parser_error err = parser_pop_next(p, &line);
			if (err == PARSER_ERR_NONE && line == NULL)
				break;
			if (err != PARSER_ERR_NONE) {
				printf("Error: %d\n", (int)err);
				continue;
			}

			struct exec_result result = execute_command_line(line);
			last_retcode = result.return_code;
			command_line_delete(line);

			if (result.need_exit != 0) {
				parser_delete(p);
				return result.return_code;
			}
		}
	}
	parser_delete(p);
	return last_retcode;
}
