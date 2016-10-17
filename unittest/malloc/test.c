#include "stdlib.h"

struct S {
  char c;
  int i;
  int a;
  int b;
  int d;
  int e;
  int f;
  int g;
  int h;
  int j;
  int k;
  int l;
};

static void foo(struct S *s) {
  printf("%d\n", s->i);
}
void foo1 (char *str) {
  printf("%s\n", str);
}

int main(int argc, char **argv) {

	struct S s;
	foo(&s);
  size_t sz = argc;
  char * m = malloc (argc);
	argv[0] = m;
  //memset (m, 0, argc);
  free(m);
  foo1(m);
	return 0;
}
