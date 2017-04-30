/* JSex library
 * by Vikman
 * April 28, 2017
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <regex.h>
#include <jsex.h>

#define error(format, ...) fprintf(stderr, "ERROR: " format "\n", ##__VA_ARGS__)

#ifdef DEBUG
#define debug(format, ...) fprintf(stderr, "DEBUG: " format "\n", ##__VA_ARGS__)
#else
#define debug(...)
#endif

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

typedef struct jsex_token_t {
    int type;
    char *string;
} jsex_token_t;

static const char * PATTERNS[] = {
    "^ +",
    "^\\(",
    "^\\)",
    "^\\[",
    "^\\]",
    "^:",
    "^[A-Za-z0-9_]+",
    "^[0-9]*\\.[0-9]+",
    "^[0-9]+",
    "^\"[^\"]+\"|'[^\"]+'",
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

static const char * TOKENS[] = {
    "end of expression",
    "'('",
    "')'",
    "'['",
    "']'",
    "':'",
    "identifier",
    "decimal",
    "integer",
    "string",
    "'.'",
    "'&&'",
    "'||'",
    "'+'",
    "-",
    "'*'",
    "/",
    "'%'",
    "'=~'",
    "'=='",
    "'!='",
    "'>='",
    "'<='",
    "'>'",
    "'<'",
    "'!'"
};

static const char * KEYWORD_IN = "in";
static const char * KEYWORD_ALL = "all";
static const char * KEYWORD_ANY = "any";
static const char * KEYWORD_NULL = "null";

static const char * FUNCTION_INT = "int";
static const char * FUNCTION_SIZE = "size";
static const char * FUNCTION_STRING = "str";
static const char * FUNCTION_FLOAT = "float";

static regex_t *regexes = NULL;

static jsex_token_t* jsex_lexer(const char *input);
static void jsex_regex_compile();
static void jsex_token_free(jsex_token_t *tokens);
static int jsex_lexer_next(const char *input, int *offset);
static int jsex_parse_expression(jsex_token_t **tokens);
static int jsex_parse_expression_nested(jsex_token_t **tokens);
static int jsex_parse_function(jsex_token_t **tokens);
static int jsex_parse_variable(jsex_token_t **tokens);
static int jsex_parse_loop(jsex_token_t **tokens);
static int jsex_parse_null(jsex_token_t **tokens);
static int jsex_parse_float(jsex_token_t **tokens);
static int jsex_parse_integer(jsex_token_t **tokens);
static int jsex_parse_string(jsex_token_t **tokens);

/* Public functions ***********************************************************/

int jsex_parse(const char *input) {
    int result;
    jsex_token_t *tokens_tmp;
    jsex_token_t *tokens = jsex_lexer(input);

    if (!tokens) {
        return -1;
    }

    tokens_tmp = tokens;
    result = jsex_parse_expression(&tokens_tmp);

    if (result == 0 && tokens_tmp->type != LEX_NONE) {
        error("Expected %s, got '%s'", TOKENS[LEX_NONE], tokens_tmp->string);
        result = -1;
    }

    jsex_token_free(tokens);
    return result;
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

/* Lexer functions ************************************************************/

jsex_token_t* jsex_lexer(const char *input) {
    int token;
    int i = 0;
    int offset;
    jsex_token_t *tokens = NULL;

    debug("jsex_lexer(): %s", input);

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
        error("At jsex_lexer(): near '%.10s'", input);
        jsex_token_free(tokens);
        return NULL;
    }

    return tokens;
}

void jsex_regex_compile() {
    int i;
    int errcode;
    char errbuf[128];

    regexes = malloc(sizeof(regex_t) * N_PATTERNS);

    if (!regexes) {
        error("At malloc()");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < N_PATTERNS; i++) {
        errcode = regcomp(regexes + i, PATTERNS[i], REG_EXTENDED);

        if (errcode) {
            regerror(errcode, regexes + i, errbuf, 128);
            error("regcomp(%s): %s", PATTERNS[i], errbuf);
            exit(EXIT_FAILURE);
        }
    }
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

int jsex_lexer_next(const char *input, int *offset) {
    int i;
    int errcode;
    char errbuf[128];
    regmatch_t match;

    if (!*input) {
        // Empty string
        debug("jsex_lexer_next(): [%s]", TOKENS[LEX_NONE]);
        *offset = 0;
        return LEX_NONE;
    }

    for (i = 0; i < N_PATTERNS; i++) {
        errcode = regexec(regexes + i, input, 1, &match, 0);

        switch (errcode) {
        case 0:
            *offset = match.rm_eo;
            debug("jsex_lexer_next(): [%s] %.*s", TOKENS[i], (int)match.rm_eo, input);
            return i;

        case REG_NOMATCH:
            break;

        default:
            regerror(errcode, regexes + i, errbuf, 128);
            error("regexec(): %s", errbuf);
            return -1;
        }
    }

    // Unknown token
    return -1;
}

/* Parser functions ***********************************************************/

int jsex_parse_expression(jsex_token_t **tokens) {
    int result;

    debug("jsex_parse_expression(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    switch ((*tokens)->type) {
    case LEX_LPAREN:
        result = jsex_parse_expression_nested(tokens);
        break;

    case LEX_ID:
        switch ((*tokens)[1].type) {
        case LEX_LPAREN:
            result = jsex_parse_function(tokens);
            break;

        default:
            if (strcmp((*tokens)->string, KEYWORD_ALL) == 0 || strcmp((*tokens)->string, KEYWORD_ANY) == 0) {
                result = jsex_parse_loop(tokens);
            } else if (strcmp((*tokens)->string, KEYWORD_NULL) == 0) {
                result = jsex_parse_null(tokens);
            } else {
                result = jsex_parse_variable(tokens);
            }
        }

        break;

    case LEX_FLOAT:
        result = jsex_parse_float(tokens);
        break;

    case LEX_INTEGER:
        result = jsex_parse_integer(tokens);
        break;

    case LEX_STRING:
        result = jsex_parse_string(tokens);
        break;

    case LEX_MINUS:
        ++(*tokens);
        result = jsex_parse_expression(tokens);

        if (result < 0) {
            // Make it negative (number)
        }

        break;

    case LEX_BANG:
        ++(*tokens);
        result = jsex_parse_expression(tokens);

        if (!result) {
            // Make it negative (bool)
        }

        break;

    default:
        error("unexpected token '%s'", (*tokens)->string);
        result = -1;
    }

    if (result == 0) {
        switch ((*tokens)->type) {
        case LEX_AND:
        case LEX_OR:
        case LEX_PLUS:
        case LEX_MINUS:
        case LEX_TIMES:
        case LEX_SLASH:
        case LEX_MOD:
        case LEX_MATCH:
        case LEX_EQUAL:
        case LEX_NEQUAL:
        case LEX_GEQ:
        case LEX_LEQ:
        case LEX_GREATER:
        case LEX_LESS:
            ++(*tokens);
            result = jsex_parse_expression(tokens);
        }
    }

    return result;
}

int jsex_parse_expression_nested(jsex_token_t **tokens) {
    debug("jsex_parse_expression_nested(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    if ((*tokens)->type != LEX_LPAREN) {
        error("Expected %s, got '%s'", TOKENS[LEX_LPAREN], (*tokens)->string);
        return -1;
    }

    ++(*tokens);

    if (jsex_parse_expression(tokens) < 0) {
        return -1;
    }

    if ((*tokens)->type != LEX_RPAREN) {
        error("Expected %s, got '%s'", TOKENS[LEX_RPAREN], (*tokens)->string);
        return -1;
    }

    ++(*tokens);
    return 0;
}

int jsex_parse_function(jsex_token_t **tokens) {
    debug("jsex_parse_function(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    if ((*tokens)->type != LEX_ID) {
        error("Expected %s, got '%s'", TOKENS[LEX_ID], (*tokens)->string);
        return -1;
    }

    if (strcmp((*tokens)->string, FUNCTION_INT)) {

    } else if (strcmp((*tokens)->string, FUNCTION_SIZE)) {

    } else if (strcmp((*tokens)->string, FUNCTION_STRING)) {

    } else if (strcmp((*tokens)->string, FUNCTION_FLOAT)) {

    } else {
        error("Invalid function");
        return -1;
    }

    ++(*tokens);

    if ((*tokens)->type != LEX_LPAREN) {
        error("Expected %s, got '%s'", TOKENS[LEX_LPAREN], (*tokens)->string);
        return -1;
    }

    ++(*tokens);

    if (jsex_parse_expression(tokens) < 0) {
        return -1;
    }

    if ((*tokens)->type != LEX_RPAREN) {
        error("Expected %s, got '%s'", TOKENS[LEX_RPAREN], (*tokens)->string);
        return -1;
    }

    ++(*tokens);
    return 0;
}

int jsex_parse_variable(jsex_token_t **tokens) {
    debug("jsex_parse_variable(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    if ((*tokens)->type != LEX_ID) {
        error("Expected %s, got '%s'", TOKENS[LEX_ID], (*tokens)->string);
        return -1;
    }

    ++(*tokens);

    switch ((*tokens)->type) {
    case LEX_LBRACKET:
        ++(*tokens);

        if (jsex_parse_expression(tokens) < 0) {
            return -1;
        }

        if ((*tokens)->type != LEX_RBRACKET) {
            error("Expected %s, got '%s'", TOKENS[LEX_RBRACKET], (*tokens)->string);
            return -1;
        }

        ++(*tokens);
        break;

    case LEX_DOT:
        ++(*tokens);

        if (jsex_parse_variable(tokens) < 0) {
            return -1;
        }

        break;
    }

    return 0;
}

int jsex_parse_loop(jsex_token_t **tokens) {
    debug("jsex_parse_loop(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    if ((*tokens)->type != LEX_ID) {
        error("Expected LEX_ID");
        return -1;
    }

    if (strcmp((*tokens)->string, KEYWORD_ALL) == 0) {

    } else if (strcmp((*tokens)->string, KEYWORD_ANY) == 0) {

    } else {
        error("Expected '%s' or '%s', got '%s'", KEYWORD_ALL, KEYWORD_ANY, (*tokens)->string);
        return -1;
    }

    ++(*tokens);

    if ((*tokens)->type != LEX_ID) {
        error("Expected %s, got '%s'", TOKENS[LEX_ID], (*tokens)->string);
        return -1;
    }

    ++(*tokens);

    if (!((*tokens)->type == LEX_ID && strcmp((*tokens)->string, KEYWORD_IN) == 0)) {
        error("Expected %s, got '%s'", TOKENS[LEX_ID], (*tokens)->string);
        return -1;
    }

    ++(*tokens);

    if (jsex_parse_variable(tokens) < 0) {
        return -1;
    }

    if ((*tokens)->type != LEX_COLON) {
        error("Expected %s, got '%s'", TOKENS[LEX_COLON], (*tokens)->string);
        return -1;
    }

    ++(*tokens);

    if (jsex_parse_expression_nested(tokens) < 0) {
        return -1;
    }

    return 0;
}

int jsex_parse_null(jsex_token_t **tokens) {
    debug("jsex_parse_null(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    if (!((*tokens)->type == LEX_ID && strcmp((*tokens)->string, KEYWORD_NULL) == 0)) {
        error("Expected '%s', got '%s'", KEYWORD_NULL, (*tokens)->string);
        return -1;
    }

    ++(*tokens);
    return 0;
}

int jsex_parse_float(jsex_token_t **tokens) {
    debug("jsex_parse_float(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    if ((*tokens)->type != LEX_FLOAT) {
        error("Expected %s, got '%s'", TOKENS[LEX_FLOAT], (*tokens)->string);
        return -1;
    }

    ++(*tokens);
    return 0;
}

int jsex_parse_integer(jsex_token_t **tokens) {
    debug("jsex_parse_integer(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    if ((*tokens)->type != LEX_INTEGER) {
        error("Expected %s, got '%s'", TOKENS[LEX_INTEGER], (*tokens)->string);
        return -1;
    }

    ++(*tokens);
    return 0;
}

int jsex_parse_string(jsex_token_t **tokens) {
    debug("jsex_parse_string(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    if ((*tokens)->type != LEX_STRING) {
        error("Expected %s, got '%s'", TOKENS[LEX_STRING], (*tokens)->string);
        return -1;
    }

    ++(*tokens);
    return 0;
}
