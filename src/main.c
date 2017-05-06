#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <jsex.h>

int main(int argc, char **argv) {
    int i;
    char * line;
    char * delimiter;
    size_t linecap;
    jsex_t * jsex;
    cJSON * json;

    if (argc < 2) {
        fprintf(stderr, "ERROR: No JSON given.\nSyntax: %s <JSON> [ <query> ]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (json = cJSON_Parse(argv[1]), !json) {
        fprintf(stderr, "ERROR: Parsing input JSON.\n");
        return EXIT_FAILURE;
    }

    if (argc == 2) {
        while (getline(&line, &linecap, stdin) >= 0) {
            delimiter = strchr(line, '\n');

            if (delimiter) {
                *delimiter = '\0';
            }

            if (jsex = jsex_parse(line), jsex) {
                printf("Result: %s\n", jsex_exec(jsex, json) ? "True" : "False");
                jsex_free(jsex);
            } else {
                printf("JSex parser error.\n\n");
            }
        }
    } else {
        for (i = 2; i < argc; i++) {
            printf("\nParsing: %s\n", argv[i]);

            if (jsex = jsex_parse(argv[i]), jsex) {
                printf("Result: %s\n", jsex_exec(jsex, json) ? "True" : "False");
                jsex_free(jsex);
            } else {
                printf("JSex parser error.\n");
            }
        }
    }

    jsex_cleanup();
    return EXIT_SUCCESS;
}
