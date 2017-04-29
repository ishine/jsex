#include <stdlib.h>
#include <stdio.h>
#include "jsex.h"

int main(int argc, char **argv) {
    int token;
    off_t offset;
    off_t match_off;

    jsex_init();

    if (argc < 2) {
        printf("Syntax: %s <input>\n", argv[0]);
        return EXIT_FAILURE;
    }

    for (offset = 0; (token = jsex_lexer(argv[1] + offset, &match_off)), token >= 0 && match_off > 0; offset += match_off) {
        if (token > 0) {
            printf("[%d]\t%.*s\n", token, (int)match_off, argv[1] + offset);
        }
    }

    jsex_stop();

    if (token < 0) {
        fprintf(stderr, "ERROR: near '%s'\n", argv[1] + offset);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
