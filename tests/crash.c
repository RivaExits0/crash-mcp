#include <stdio.h>
#include <stdlib.h>

void boom(int x) {
    int *p = NULL;
    *p = x; /* crash */
}

int main(void) {
    boom(42);
    return 0;
}
