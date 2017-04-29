#include <stdlib.h>
#include <stdio.h>
#include "jsex.h"

int main(int argc, char **argv) {
    jsex_token_t *tokens;
    jsex_token_t *token;

    if (argc < 2) {
        printf("Syntax: %s <input>\n", argv[0]);
        return EXIT_FAILURE;
    }

    tokens = jsex_lexer(argv[1]);

    if (tokens) {
        for (token = tokens; token->type; token++) {
            printf("[%d]\t%s\n", token->type, token->string);
        }

        jsex_token_free(tokens);
        return EXIT_SUCCESS;
    } else {
        return EXIT_FAILURE;
    }
}
