#include "stdlib.h"

struct S {
  char c[2];
  char *p;
  int i;
};

struct S gs;

void foo(char *c) {
  printf("%p\n", c);
}

int main(int argc, char **argv) {

int g = 0;
  struct S s;
  s.i = 0;
  char a;
  char aa;
  char *p = (char *)&a;
  g = *p;
  if (argc > 1) {
    a += argc;
  }
  else
    a = argc * 2;
  //foo(a);

  if (a > argc)
    s.c[0] = a;

  int b;
  if (a > 0)
    b = a;

  g = aa;
  printf("%p %d %d\n", &a, s.c[0], b);

	return 0;
}
