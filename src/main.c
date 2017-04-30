#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <jsex.h>

int main(int argc, char **argv) {
    int i;
    char *line;
    char *delimiter;
    size_t linecap;

    if (argc == 1) {
        while (getline(&line, &linecap, stdin) >= 0) {
            delimiter = strchr(line, '\n');

            if (delimiter) {
                *delimiter = '\0';
            }

            printf(jsex_parse(line) ? "JSex parser error.\n\n" : "\n");
        }
    } else {
        for (i = 1; i < argc; i++) {
            printf("\nParsing: %s\n", argv[i]);

            if (jsex_parse(argv[i])) {
                printf("JSex parser error.\n");
            }
        }
    }

    jsex_cleanup();
    return EXIT_SUCCESS;
}
