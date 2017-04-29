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
#include <string.h>
#include <stdio.h>
#include <regex.h>
#include "jsex.h"

#define LEX_NONE        0
#define LEX_LPAREN      1
#define LEX_RPAREN      2
#define LEX_LBRACKET    3
#define LEX_RBRACKET    4
#define LEX_COLON       5
#define LEX_ID          6
#define LEX_FLOAT       7
#define LEX_INTEGER     8
#define LEX_STRING      9
#define LEX_DOT         10
#define LEX_AND         11
#define LEX_OR          12
#define LEX_PLUS        13
#define LEX_MINUS       14
#define LEX_TIMES       15
#define LEX_SLASH       16
#define LEX_MOD         17
#define LEX_MATCH       18
#define LEX_EQUAL       19
#define LEX_NEQUAL      20
#define LEX_GEQ         21
#define LEX_LEQ         22
#define LEX_GREATER     23
#define LEX_LESS        24
#define LEX_BANG        25
#define N_PATTERNS      26

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
    "^!"
};

static regex_t *regexes = NULL;

static void jsex_regex_compile() {
    int i;
    int errcode;
    char errbuf[128];

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

void jsex_cleanup() {
    int i;

    if (regexes) {
        for (i = 0; i < N_PATTERNS; i++) {
            regfree(regexes + i);
        }

        free(regexes);
        regexes = NULL;
    }
}

static int jsex_lexer_next(const char *input, int *offset) {
    int i;
    int errcode;
    char errbuf[128];
    regmatch_t match;

    if (!*input) {
        // Empty string
        *offset = 0;
        return LEX_NONE;
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

void jsex_token_free(jsex_token_t *tokens) {
    jsex_token_t *token;

    if (tokens) {
        for (token = tokens; token->type != LEX_NONE; token++) {
            free(token->string);
        }

        free(tokens);
    }
}

jsex_token_t* jsex_lexer(const char *input) {
    int token;
    int i = 0;
    int offset;
    jsex_token_t *tokens = NULL;

    if (!regexes) {
        jsex_regex_compile();
    }

    while (token = jsex_lexer_next(input, &offset), token >= 0 && offset > 0) {
        if (token > 0) {
            tokens = realloc(tokens, sizeof(jsex_token_t) * (i + 1));
            tokens[i].type = token;
            tokens[i].string = strndup(input, offset);
            i++;
        }

        input += offset;
    }

    tokens = realloc(tokens, sizeof(jsex_token_t) * (i + 1));
    tokens[i].type = token;
    tokens[i].string = strndup(input, offset);

    if (token < 0) {
        fprintf(stderr, "ERROR: jsex_lexer(): near '%s'\n", input);
        jsex_token_free(tokens);
        return NULL;
    }

    return tokens;
}
