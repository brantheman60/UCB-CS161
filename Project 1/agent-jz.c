#define BUFLEN 16

#include <stdio.h>
#include <string.h>

int nibble_to_int(char nibble) {
    if ('0' <= nibble && nibble <= '9') return nibble - '0'; //int(nibble)
    else return nibble - 'a' + 10; // a=10, b=11, ..., f=15
}

void dehexify() {
    struct {
        char answer[BUFLEN]; //16 char
        char buffer[BUFLEN]; //16 char
    } c;
    int i = 0, j = 0;

    gets(c.buffer);

    while (c.buffer[i]) { //until you get '\0'; if i>=16, SEGFAULT
        if (c.buffer[i] == '\\' && c.buffer[i+1] == 'x') {  // Eg. \x4f
            int top_half = nibble_to_int(c.buffer[i+2]);    // 4->4
            int bottom_half = nibble_to_int(c.buffer[i+3]); // f->15
            c.answer[j] = top_half << 4 | bottom_half; //merge them togthr
            i += 3;
        } else {
            c.answer[j] = c.buffer[i];
        }
        i++; j++;
    }

    c.answer[j] = 0;
    printf("%s\n", c.answer);
    fflush(stdout);
}

int main() {
    while (!feof(stdin)) {
        dehexify();
    }
    return 0;
}
