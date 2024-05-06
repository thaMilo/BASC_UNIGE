#include <capstone/capstone.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

void get_instruction_pointer(pid_t pid, unsigned long *rip) {
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == 0) {
    *rip = regs.rip;
  } else {
    perror("ptrace(PTRACE_GETREGS)");
  }
}

void get_assembly_mnemonics(pid_t pid, unsigned long rip) {
  csh handle;
  cs_insn *insn;
  size_t count;
  long data = ptrace(PTRACE_PEEKDATA, pid, rip, NULL);
  unsigned char code[8];
  memcpy(code, &data, sizeof(data));
  char *assembly_mnemonics = NULL;

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
    fprintf(stderr, "Failed to initialize Capstone\n");
  }

  count = cs_disasm(handle, code, sizeof(code), rip, 0, &insn);

  if (count > 0) {
    for (size_t i = 0; i < count; i++) {
      printf("0x%lx: %s %s\n", insn[i].address, insn[i].mnemonic,
             insn[i].op_str);
    }
    cs_free(insn, count);
  } else {
    fprintf(stderr, "Failed to disassemble instruction at 0x%lx\n", rip);
  }
  cs_close(&handle);
}

int trace_execution(char *program_to_execute,
                    char *program_to_execute_arguments[]) {
  pid_t pid;
  int status;
  long machine_code_instruction_num = 0;
  unsigned long rip;

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
      get_instruction_pointer(pid, &rip);
      get_assembly_mnemonics(pid, rip);
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
