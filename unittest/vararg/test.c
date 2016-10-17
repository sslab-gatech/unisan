#include "stdlib.h"

int main() {
  int (*fp)(const char *, ...) = printf;

  fp("hello %s\n", "world");
	return 0;
}
