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

void hello(char *str) {
  printf("%s", str);
}

unsigned long *define_fp(unsigned long *p) {
  *p = hello;
  return *p;
}

int main(int argc, char **argv) {
  fp = hello;
  define_fp(&fp);
  fp_get_fp = get_fp;
  // function pointer returned by direct call
  //void *fp1 = get_fp();
  // function pointer returned by indirect call
  void *fp1 = fp_get_fp();
  void (*fp_foo) (char *, void *) = foo;
  fp_foo("hello world\n", fp1);

	return 0;
}
