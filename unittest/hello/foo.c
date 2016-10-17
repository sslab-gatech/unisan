#include "foo.h"

struct S {
  int s;
};

void foo() {
  int a = 123;
  int *p_a;
  char *b = malloc(a);
  int c[10];
  struct S s;

  int i = a;
  char dy[i];
  printf("hello world %p %d %p %d %p\n", p_a, a, b, c[0], dy);
}
