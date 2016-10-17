#include "stdlib.h"

struct S {
  char c;
  int i;
};

static void foo(struct S *s) {
  printf("%d\n", s->i);
}

int main(int argc, char **argv) {

  struct S s;
  char a;
  s.i = a;
  foo(&s);
	return 0;
}
