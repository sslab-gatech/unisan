#include "stdlib.h"

void foo(void *arg) {
}
int main() {
  int a;
  int b = 1;
  //void *pa = &a;
  //foo(pa);
  memcpy(&a, &b, sizeof(int));
  printf("a=%d\n", a);
	return 0;
}
