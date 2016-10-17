#include <stdio.h>

int foo (int x) {
  if (x < 0) 
    x = -x;
  return (x+1);
}
int main(int argc, char **argv) {
  int z = foo(1);
  printf("z=%d\n", z);
	return 0;
}
