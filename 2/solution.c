#include "parser.h"
#include "rlist.h"

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

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

static struct exec_result
execute_command_line(const struct command_line *line)
{
	assert(line != NULL);

	size_t cmd_count = 0;
	struct rlist logical_chain_reversed;
	rlist_create(&logical_chain_reversed);

	struct expr *iter = line->head;
	while (iter != NULL) {
		switch (iter->type) {
			case EXPR_TYPE_COMMAND: {
				struct chain_command *cc = calloc(1, sizeof(struct chain_command));
				if (cc == NULL) {
					puts("calloc error\n");
					free_cmd_rlist(&logical_chain_reversed);
					return make_result(0, 0);
				}

				cc->expression = iter;
				rlist_add_tail(&logical_chain_reversed, &cc->link);
				++cmd_count;
				break;
			}

			default: {
				break;
			}
		}

		iter = iter->next;
	}

	size_t child_size = 0;
	pid_t *children_pids = calloc(cmd_count, sizeof(pid_t));
	if (children_pids == NULL) {
		puts("calloc error\n");
		free_cmd_rlist(&logical_chain_reversed);
		return make_result(0, 0);
	}

	int *pipes_fds = calloc(2 * cmd_count, sizeof(int));
	if (pipes_fds == NULL) {
		puts("calloc error\n");
		free_cmd_rlist(&logical_chain_reversed);
		free(children_pids);
		return make_result(0, 0);
	}

	for (size_t i = 0; i < cmd_count - 1; ++i) {
		if (pipe(pipes_fds + 2 * i + 1) != 0) {
			puts("pipe creation error\n");

			for (size_t fd_idx = 1; fd_idx < i; ++fd_idx) {
				close(pipes_fds[fd_idx]);
			}

			free(children_pids);
			free(pipes_fds);
			free_cmd_rlist(&logical_chain_reversed);
			return make_result(0, 0);
		}

		int tmp = pipes_fds[2 * i + 1];
		pipes_fds[2 * i + 1] = pipes_fds[2 * (i + 1)];
		pipes_fds[2 * (i + 1)] = tmp;
	}

	pipes_fds[0] = STDIN_FILENO;
	pipes_fds[2 * cmd_count - 1] = STDOUT_FILENO;

	FILE *output = NULL;
	if (line->out_type != OUTPUT_TYPE_STDOUT) {
		output = fopen(line->out_file, line->out_type == OUTPUT_TYPE_FILE_NEW ? "w" : "a");
		if (output == NULL) {
			puts("out file open error\n");
			free_cmd_rlist(&logical_chain_reversed);
			free(children_pids);
			free(pipes_fds);
			return make_result(0, 0);
		}

		pipes_fds[2 * cmd_count - 1] = fileno(output);
	}

	size_t i = 0;
	struct rlist *cmd_iter;

	rlist_foreach(cmd_iter, &logical_chain_reversed) {
		struct chain_command *cc = container_of(cmd_iter, struct chain_command, link);
		const struct expr *expression = cc->expression;

		if (strcmp("cd", expression->cmd.exe) == 0) {
			if (cmd_count == 1 && handle_cd_command(expression) != 0) {
				puts("cd error\n");
				free_cmd_rlist(&logical_chain_reversed);

				if (output != NULL) {
					fclose(output);
				}

				for (size_t fd_idx = 1; fd_idx < 2 * (cmd_count - 1); ++fd_idx) {
					close(pipes_fds[fd_idx]);
				}

				free(children_pids);
				free(pipes_fds);
				return make_result(0, -1);
			}
		}
		else if (strcmp("exit", expression->cmd.exe) == 0) {
			if (i == cmd_count - 1) {
				free_cmd_rlist(&logical_chain_reversed);
				if (output != NULL) {
					fclose(output);
				}

				for (size_t fd_idx = 1; fd_idx < 2 * (cmd_count - 1); ++fd_idx) {
					close(pipes_fds[fd_idx]);
				}
				free(pipes_fds);

				for (size_t child_idx = 0; child_idx < child_size; ++child_idx) {
					int status;
					waitpid(children_pids[child_idx], &status, 0);
				}
				free(children_pids);

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
					free_cmd_rlist(&logical_chain_reversed);

					if (output != NULL) {
						fclose(output);
					}

					for (size_t fd_idx = 1; fd_idx < 2 * (cmd_count - 1); ++fd_idx) {
						close(pipes_fds[fd_idx]);
					}
					free(pipes_fds);
					free(children_pids);

					return make_result(1, 0);
				}

				case 0: {
					for (size_t fd_idx = 1; fd_idx < 2 * cmd_count - 1; ++fd_idx) {
						if (fd_idx != 2 * i + 1 && fd_idx != 2 * i) {
							close(pipes_fds[fd_idx]);
						}
					}

					if (dup2(pipes_fds[2 * i], STDIN_FILENO) != STDIN_FILENO) {
						puts("dup2 error\n");
						return make_result(1, 0);
					}

					if (dup2(pipes_fds[2 * i + 1], STDOUT_FILENO) != STDOUT_FILENO) {
						puts("dup2 error\n");
						return make_result(1, 0);
					}

					execute_cmd(expression);
					break;
				}

				default: {
					children_pids[child_size++] = child_pid;
					break;
				}
			}
		}

		++i;
	}

	for (i = 1; i < 2 * (cmd_count - 1); ++i) {
		close(pipes_fds[i]);
	}

	if (output != NULL) {
		fclose(output);
	}

	int ret_code = 0;

	for (size_t child_idx = 0; child_idx < child_size; ++child_idx) {
		int status;
		waitpid(children_pids[child_idx], &status, 0);

		if (WIFEXITED(status)) {
			ret_code = WEXITSTATUS(status);
		}
	}

	free(children_pids);
	free(pipes_fds);
	free_cmd_rlist(&logical_chain_reversed);

	return make_result(0, ret_code);
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
