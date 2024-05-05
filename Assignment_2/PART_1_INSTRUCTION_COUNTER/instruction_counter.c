#include <stdio.h>

int main(int argc, char *argv[]) {
  // the first argument in argv is the name of a program and the other ones are
  // the arguments

  char *program_name = argv[1];
  char *arguments[argc - 1];

  for (int i = 2; i < argc; i++) {
    arguments[i - 2] = argv[i];
  }

  printf("Tracing %s\n", program_name);

  // execute the program counting how many system instruction are being called
}
