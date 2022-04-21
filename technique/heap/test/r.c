#include <stdlib.h>

int main()
{
  long int *p = malloc(0x1000);
  p[0] = 0;
  p[1] = 0x421;
  p[2] = 0;
  p[3] = 0;
  p[(0x420/8) + 1] = 0x21;
  p[(0x420/8) + 2] = (long int)&p[(0x420/8)];
  p[(0x420/8) + 3] = (long int)&p[(0x420/8)];
  p[(0x420/8) + (0x20/8)] = 0x20;
  free(&p[2]);
}