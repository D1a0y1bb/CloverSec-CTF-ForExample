#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(){ system("cat /flag"); }
int main(){ char buf[64]; read(0, buf, 256); puts("bye"); return 0; }
