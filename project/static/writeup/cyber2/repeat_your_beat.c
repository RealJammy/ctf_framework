#include <stdio.h>
#include <string.h>

int main(void) {
  char buf [256];
  int loop_var;

  loop_var = 0;
  puts("Let me repeat your beat!\n\tYou go first!");
  fflush(stdout);
  while (loop_var == 0) {
    fgets(buf,0x256,stdin);
    printf(buf);
    fflush(stdout);
  }
  return 0;
}
