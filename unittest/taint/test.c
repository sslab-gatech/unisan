#include <stdio.h>

void (*fp) (char *);

void *(*fp_get_fp) ();

void *get_fp() {
  return (void *)fp;
}

void foo(char *str, void *fp1) {
  void (*fp2) (char *) = (void (*) (char *))fp1;
  fp2(str);
}

void hello(long a) {
  printf("%d\n", a);
}

int main(int argc, char **argv) {
  char *m = malloc(10);
  memset(m, 0, 10);
  int a = argc;
  fp = hello;
  fp_get_fp = get_fp;
  void *fp1 = fp_get_fp();
  void (*fp_foo) (char *, void *) = foo;
  fp_foo(m, fp1);
	return 0;
}
