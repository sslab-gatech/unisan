#include "stdlib.h"

struct gep {
  char c;
  int i;
};

void main() {
  //struct gep *pg;
  //(*pg).i = 2;
  //struct gep g;
  //g.i = 1;
  //char *c;
  //c[1] = 0;
  char c[3];
  char *p = (char *)c;
  p[0] = 0;
}
