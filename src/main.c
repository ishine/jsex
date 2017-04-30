#include <stdlib.h>
#include <stdio.h>
#include <jsex.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Syntax: %s <input>\n", argv[0]);
        return EXIT_FAILURE;
    }

    return jsex_parse(argv[1]) ? EXIT_FAILURE : EXIT_SUCCESS;
}
