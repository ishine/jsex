#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <jsex.h>

int main(int argc, char **argv) {
    int i;
    char * line;
    char * delimiter;
    char * cresult;
    size_t linecap = 0;
    jsex_t * jsex;
    cJSON * json;
    cJSON * jresult;

    if (argc < 2) {
        fprintf(stderr, "ERROR: No JSON given.\nSyntax: %s <JSON> [ <query> ]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (json = cJSON_Parse(argv[1]), !json) {
        fprintf(stderr, "ERROR: Parsing input JSON.\n");
        return EXIT_FAILURE;
    }

    if (argc == 2) {
        while (1) {
            printf(">>> ");
            fflush(stdout);
            if (getline(&line, &linecap, stdin) < 0) {
                break;
            }

            delimiter = strchr(line, '\n');

            if (delimiter) {
                *delimiter = '\0';
            }

            if (strlen(line) == 0) {
                continue;
            }

            if (jsex = jsex_parse(line), jsex) {
                jresult = jsex_exec(jsex, json);
                cresult = cJSON_PrintUnformatted(jresult);
                printf("%s\n\n", cresult);
                free(cresult);
                cJSON_Delete(jresult);
                jsex_free(jsex);
            } else {
                printf("JSex parser error.\n\n");
            }
        }

        printf("\n");
    } else {
        for (i = 2; i < argc; i++) {
            printf("Parsing: %s\n", argv[i]);

            if (jsex = jsex_parse(argv[i]), jsex) {
                jresult = jsex_exec(jsex, json);
                cresult = cJSON_PrintUnformatted(jresult);
                printf("Result: %s\n\n", cresult);
                free(cresult);
                cJSON_Delete(jresult);
                jsex_free(jsex);
            } else {
                printf("JSex parser error.\n\n");
            }
        }
    }

    jsex_cleanup();
    return EXIT_SUCCESS;
}
