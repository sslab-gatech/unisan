#include "stdlib.h"

struct gep {
  char c;
  int i;
};

int main() {

  char c[3];
  char *pc = c;
  int i = 0;
  while (i < 3) {
    ++i;
    pc[i] = 9;
  }

	return 0;
}
