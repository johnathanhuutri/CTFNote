// #include <stdlib.h>

// int main()
// {
// 	long int *p0 = malloc(0x420);
//     long int *p = malloc(0x20);
//     long int *p1 = malloc(0x420);
//     malloc(0x10);

//     p0[1] = 0x451;
//     p0[2] = &p0[0];
//     p0[3] = &p0[0];

//     p1[-2] = 0x450;
//     p1[-1] = 0x610;
    
//     // free(p0);
//     free(p1);
// }

#include <stdlib.h>

int main()
{
    long int *p0 = malloc(0x420);
    long int *p1 = malloc(0x20);
    long int *p2 = malloc(0x420);
    malloc(0x10);

    p0[0] = 0;
    p0[1] = 0x450;
    p0[2] = &p0[0];
    p0[3] = &p0[0];

    p2[-2] = 0x450;
    p2[-1] = 0x430;

    free(p2);
}