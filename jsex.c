/* JSex library
 * by Vikman
 * April 28, 2017
 */

/*
size(a.b) > 2 && any x in a.b: (x =~ "sg*" || int(x) == 4)
a.b == 4 && all x in a.c: (x.value > 7 || x.comment == null)

keywords: exists, any, all, in, size, null, int, str, float
comparators: ==, !=, <, >, <=, >=, =~
operators: [, ], +, -, *, /, %, &&, ||, !
tokens: ., :, (, ), ", '
*/

#include <stdlib.h>
#include <stdio.h>
#include <regex.h>

#define NONE        0
#define LPAREN      1
#define RPAREN      2
#define LBRACKET    3
#define RBRACKET    4
#define COLON       5
#define ID          6
#define FLOAT       7
#define INTEGER     8
#define STRING      9
#define DOT         10
#define AND         11
#define OR          12
#define PLUS        13
#define MINUS       14
#define TIMES       15
#define SLASH       16
#define MOD         17
#define MATCH       18
#define EQUAL       19
#define NEQUAL      20
#define GEQ         21
#define LEQ         22
#define GREATER     23
#define LESS        24
#define BANG        25
#define N_PATTERNS  26

static const char* PATTERNS[] = {
    "^ +",
    "^\\(",
    "^\\)",
    "^\\[",
    "^\\]",
    "^:",
    "^[A-Za-z0-9_]+",
    "^^[0-9]*\\.[0-9]+",
    "^^[0-9]+",
    "^\".+\"|'.+'",
    "^\\.",
    "^&&",
    "^\\|\\|",
    "^\\+",
    "^-",
    "^\\*",
    "^/",
    "^%",
    "^=~",
    "^==",
    "^!=",
    "^>=",
    "^<=",
    "^>",
    "^<",
    "^!",
};

static regex_t *regexes = NULL;

void jsex_init() {
    int i;
    int errcode;
    char errbuf[128];

    if (regexes) {
        fprintf(stderr, "WARN: jsex_init called twice.\n");
    } else {
        regexes = malloc(sizeof(regex_t) * N_PATTERNS);

        if (!regexes) {
            fprintf(stderr, "ERROR: at malloc()\n");
            exit(EXIT_FAILURE);
        }

        for (i = 0; i < N_PATTERNS; i++) {
            errcode = regcomp(regexes + i, PATTERNS[i], REG_EXTENDED);

            if (errcode) {
                regerror(errcode, regexes + i, errbuf, 128);
                fprintf(stderr, "ERROR: regcomp(%s): %s\n", PATTERNS[i], errbuf);
                exit(EXIT_FAILURE);
            }
        }
    }
}

void jsex_stop() {
    int i;

    if (regexes) {
        for (i = 0; i < N_PATTERNS; i++) {
            regfree(regexes + i);
        }

        free(regexes);
        regexes = NULL;
    }
}

int jsex_lexer(const char *input, off_t *offset) {
    int i;
    int errcode;
    char errbuf[128];
    regmatch_t match;

    if (!*input) {
        // Empty string
        *offset = 0;
        return NONE;
    }

    if (!regexes) {
        fprintf(stderr, "WARN: JSex not initialized. Use jsex_init().\n");
        jsex_init();
    }

    for (i = 0; i < N_PATTERNS; i++) {
        errcode = regexec(regexes + i, input, 1, &match, 0);

        switch (errcode) {
        case 0:
            *offset = match.rm_eo;
            return i;

        case REG_NOMATCH:
            break;

        default:
            regerror(errcode, regexes + i, errbuf, 128);
            fprintf(stderr, "ERROR: regexec(): %s\n", errbuf);
            return -1;
        }
    }

    return -1;
}
