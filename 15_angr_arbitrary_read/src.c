#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>

char msg[] = "";
char* try_again = "Try again.";
char* good_job = "Good Job.";
uint32_t key;

void print_msg() {
  printf("%s", msg);
}

struct overflow_me {
  char buffer[16];
  char* to_print;
};

int main(int argc, char* argv[]) {
  struct overflow_me locals;
  locals.to_print = try_again;

  //print_msg();

  printf("Enter the password: ");
  scanf("%u %24s", &key, locals.buffer);

  switch (key) {case 14274378: puts(locals.to_print);; break;case 63538247: puts(try_again);; break;default: puts(try_again);; break; }

  return 0;
}