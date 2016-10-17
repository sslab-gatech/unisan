#include "stdlib.h"

int main(int argc) {
  int i;
  if (i < 0)
    i = 0;
  printf("i=%d\n", &i);
	return 0;
}
