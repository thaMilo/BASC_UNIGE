#include <errno.h> // For error handling
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h> // For accessing the instruction pointer
#include <sys/wait.h>
#include <unistd.h>

int trace_execution(char *program_to_execute,
                    char *program_to_execute_arguments[]) {
  pid_t pid;
  int status;
  long machine_code_instruction_num = 0;

  pid = fork();
  if (pid == -1) {
    perror("fork");
    return -1;
  }

  if (pid == 0) {
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execvp(program_to_execute, program_to_execute_arguments);
    perror("execvp");
    exit(EXIT_FAILURE);
  } else {
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      return machine_code_instruction_num;
    }

    while (WIFSTOPPED(status)) {
      machine_code_instruction_num++;
      ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
      waitpid(pid, &status, 0);
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
  }

  return machine_code_instruction_num;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <program> [arguments...]\n", argv[0]);
    return 1;
  }

  char *program_to_execute = argv[1];
  char *program_to_execute_arguments[argc];
  program_to_execute_arguments[0] = program_to_execute;

  for (int i = 2; i < argc; i++) {
    program_to_execute_arguments[i - 1] = argv[i];
  }

  program_to_execute_arguments[argc - 1] = NULL;

  printf("Tracing %s\n", program_to_execute);
  int instruction_count =
      trace_execution(program_to_execute, program_to_execute_arguments);
  printf("Total machine code instructions executed: %d\n", instruction_count);

  return 0;
}
