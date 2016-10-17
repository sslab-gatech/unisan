#include "stdlib.h"

struct Hello {
  char c;
  char c1;
  int a;
  long long l;
};
int g = 0;

int foo(int a) {
  printf("%d\n", a);
  return a;
}

int main() {
  printf("size of Hello: %d\n", sizeof(struct Hello));

  int a;
  int b = foo(a);
  struct Hello hello[2];
  memset(&hello[1], 1, sizeof(struct Hello));
  hello[1].a = a;
  hello[1].c = 'c';
  g = a;
  hello[0].l = a;
  foo(hello[0].a);
	return 0;
}
