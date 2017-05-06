/* JSex library
 * by Vikman
 * April 28, 2017
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <jsex.h>

#define error(format, ...) fprintf(stderr, "ERROR: " format "\n", ##__VA_ARGS__)

#ifdef DEBUG
#define debug(format, ...) fprintf(stderr, "DEBUG: " format "\n", ##__VA_ARGS__)
#else
#define debug(format, ...)
#endif

#ifdef PROFILE
#include <time.h>
#define profile_start() clock_t clock_s = clock()
#define profile_reset() clock_s = clock()
#define profile_print(name) printf("PROFILE: " name ": %.3f ms.\n", (double)(clock() - clock_s) * 1000 / CLOCKS_PER_SEC)
#else
#define profile_start()
#define profile_reset()
#define profile_print(name)
#endif

#define CJSON_INITIALIZER { NULL, NULL, NULL, 0, NULL, 0, 0, NULL }

#define LEX_NONE        0
#define LEX_LPAREN      1
#define LEX_RPAREN      2
#define LEX_LBRACKET    3
#define LEX_RBRACKET    4
#define LEX_COLON       5
#define LEX_FLOAT       6
#define LEX_INTEGER     7
#define LEX_ID          8
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
    "^[0-9]*\\.[0-9]+",
    "^[0-9]+",
    "^[A-Za-z0-9_]+",
    "^\"(\\\\\"|[^\"])*\"|'(\\\\'|[^'])*'",
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
    "end of query",
    "'('",
    "')'",
    "'['",
    "']'",
    "':'",
    "decimal",
    "integer",
    "identifier",
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

static const char * const KEYWORD_IN = "in";
static const char * const KEYWORD_ALL = "all";
static const char * const KEYWORD_ANY = "any";
static const char * const KEYWORD_NULL = "null";

static const char * const FUNCTION_INT = "int";
static const char * const FUNCTION_STRING = "str";
static const char * const FUNCTION_SIZE = "size";

static regex_t * regexes = NULL;

static jsex_token_t * jsex_lexer(const char * input);
static void jsex_regex_compile();
static void jsex_token_free(jsex_token_t * tokens);
static int jsex_lexer_next(const char * input, int * offset);

static jsex_t * jsex_parse_query(const jsex_token_t ** tokens);
static jsex_t * jsex_parse_sentence(const jsex_token_t ** tokens);
static jsex_t * jsex_parse_expression(const jsex_token_t ** tokens);
static jsex_t * jsex_parse_term(const jsex_token_t ** tokens);
static jsex_t * jsex_parse_factor(const jsex_token_t ** tokens);
static jsex_t * jsex_parse_function(const jsex_token_t ** tokens);
static jsex_t * jsex_parse_variable(const jsex_token_t ** tokens);
static jsex_t * jsex_parse_loop(const jsex_token_t ** tokens);
static jsex_t * jsex_parse_null(const jsex_token_t ** tokens);
static jsex_t * jsex_parse_float(const jsex_token_t ** tokens);
static jsex_t * jsex_parse_integer(const jsex_token_t ** tokens);
static jsex_t * jsex_parse_string(const jsex_token_t ** tokens);

static void jsex_rt_and(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_or(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_match(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_equal(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_not_equal(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_greater_equal(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_less_equal(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_greater(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_less(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_add(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_subtract(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_multiply(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_divide(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_modulo(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_negate(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_opposite(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_int(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_size(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_string(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_variable(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_loop_all(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_loop_any(const jsex_t * node, const cJSON * value, cJSON * result);
static void jsex_rt_value(const jsex_t * node, const cJSON * value, cJSON * result);

static int jsex_cast_bool(const cJSON * value);
static int jsex_cast_int(const cJSON * value);

/* Public functions ***********************************************************/

jsex_t * jsex_parse(const char *input) {
    jsex_t * node = NULL;
    jsex_token_t * tokens = NULL;
    const jsex_token_t * tokens_tmp;

    profile_start();
    tokens = jsex_lexer(input);

    if (!tokens) {
        goto error;
    }

    tokens_tmp = tokens;
    node = jsex_parse_query(&tokens_tmp);

    if (!node) {
        goto error;
    }

    if (tokens_tmp->type != LEX_NONE) {
        error("Expected %s, got '%s'", TOKENS[LEX_NONE], tokens_tmp->string);
        goto error;
    }

    jsex_token_free(tokens);
    profile_print("jsex_parse()");
    return node;

error:
    jsex_token_free(tokens);
    jsex_free(node);
    return NULL;
}

int jsex_exec(const jsex_t * node, cJSON * value) {
    cJSON result = CJSON_INITIALIZER;
    node->function(node, value, &result);
    return jsex_cast_bool(&result);
}

void jsex_free(jsex_t * node) {
    if (node) {
        cJSON_Delete(node->value);

        if (node->regex) {
            regfree(node->regex);
            free(node->regex);
        }

        jsex_free(node->args[0]);
        jsex_free(node->args[1]);
        free(node);
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

/* Lexer functions ************************************************************/

jsex_token_t * jsex_lexer(const char *input) {
    int token;
    int i = 0;
    int offset;
    jsex_token_t * tokens = NULL;

    profile_start();
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
    tokens[i].type = LEX_NONE;
    tokens[i].string = NULL;

    if (token < 0) {
        error("At jsex_lexer(): near '%.10s'", input);
        jsex_token_free(tokens);
        return NULL;
    }

    profile_print("jsex_lexer()");
    return tokens;
}

void jsex_regex_compile() {
    int i;
    int errcode;
    char errbuf[128];

    profile_start();
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

    profile_print("jsex_regex_compile()");
}

void jsex_token_free(jsex_token_t *tokens) {
    jsex_token_t * token;

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

// <query> ::= <sentence> [ ( '&&' | '||' ) <query> ]
jsex_t * jsex_parse_query(const jsex_token_t ** tokens) {
    jsex_t * node = NULL;
    jsex_t * parent;
    jsex_t * sibling;
    void (*function)(const jsex_t *, const cJSON *, cJSON *);

    debug("jsex_parse_query(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    node = jsex_parse_sentence(tokens);

    if (!node) {
        goto error;
    }

    switch ((*tokens)->type) {
    case LEX_AND:
        function = jsex_rt_and;
        break;

    case LEX_OR:
        function = jsex_rt_or;
        break;

    default:
        return node;
    }

    ++(*tokens);
    sibling = jsex_parse_query(tokens);

    if (!sibling) {
        goto error;
    }

    parent = calloc(1, sizeof(jsex_t));
    parent->function = function;
    parent->args[0] = node;
    parent->args[1] = sibling;

    return parent;

error:
    jsex_free(node);
    return NULL;
}

// <sentence> ::= <loop> | '!' <sentence> | <expression> [ ( '=~' | '==' | '!=' | '>=' | '<=' | '>' | '<' ) <sentence> ]
jsex_t * jsex_parse_sentence(const jsex_token_t ** tokens) {
    jsex_t * node = NULL;
    jsex_t * parent;
    jsex_t * sibling;
    void (*function)(const jsex_t *, const cJSON *, cJSON *);

    debug("jsex_parse_sentence(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    if ((*tokens)->type == LEX_ID && (strcmp((*tokens)->string, KEYWORD_ALL) == 0 || strcmp((*tokens)->string, KEYWORD_ANY) == 0)) {
        node = jsex_parse_loop(tokens);

        if (!node) {
            goto error;
        }
    } else if ((*tokens)->type == LEX_BANG) {
        ++(*tokens);
        node = jsex_parse_sentence(tokens);

        if (!node) {
            goto error;
        }

        parent = calloc(1, sizeof(jsex_t));
        parent->function = jsex_rt_negate;
        parent->args[0] = node;
        node = parent;
    } else {
        node = jsex_parse_expression(tokens);

        if (!node) {
            goto error;
        }
    }

    switch ((*tokens)->type) {
    case LEX_MATCH:
        function = jsex_rt_match;
        break;

    case LEX_EQUAL:
        function = jsex_rt_equal;
        break;

    case LEX_NEQUAL:
        function = jsex_rt_not_equal;
        break;

    case LEX_GEQ:
        function = jsex_rt_greater_equal;
        break;

    case LEX_LEQ:
        function = jsex_rt_less_equal;
        break;

    case LEX_GREATER:
        function = jsex_rt_greater;
        break;

    case LEX_LESS:
        function = jsex_rt_less;
        break;

    default:
        return node;
    }

    ++(*tokens);
    sibling = jsex_parse_sentence(tokens);

    if (!sibling) {
        goto error;
    }

    parent = calloc(1, sizeof(jsex_t));
    parent->function = function;
    parent->args[0] = node;
    parent->args[1] = sibling;

    return parent;

error:
    jsex_free(node);
    return NULL;
}

// <expression> ::= <term> [ ( '+' | '-' ) <expression> ]
jsex_t * jsex_parse_expression(const jsex_token_t ** tokens) {
    jsex_t * node = NULL;
    jsex_t * parent;
    jsex_t * sibling;
    void (*function)(const jsex_t *, const cJSON *, cJSON *);

    debug("jsex_parse_expression(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    node = jsex_parse_term(tokens);

    if (!node) {
        goto error;
    }

    switch ((*tokens)->type) {
    case LEX_PLUS:
        function = jsex_rt_add;
        break;

    case LEX_MINUS:
        function = jsex_rt_subtract;
        break;

    default:
        return node;
    }

    ++(*tokens);
    sibling = jsex_parse_expression(tokens);

    if (!sibling) {
        goto error;
    }

    parent = calloc(1, sizeof(jsex_t));
    parent->function = function;
    parent->args[0] = node;
    parent->args[1] = sibling;

    return parent;

error:
    jsex_free(node);
    return NULL;
}

// <term> ::= <factor> ( '*' | '/' | '%' ) <term> ]
jsex_t * jsex_parse_term(const jsex_token_t ** tokens) {
    jsex_t * node = NULL;
    jsex_t * parent;
    jsex_t * sibling;
    void (*function)(const jsex_t *, const cJSON *, cJSON *);

    debug("jsex_parse_term(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    node = jsex_parse_factor(tokens);

    if (!node) {
        goto error;
    }

    switch ((*tokens)->type) {
    case LEX_TIMES:
        function = jsex_rt_multiply;
        break;

    case LEX_SLASH:
        function = jsex_rt_divide;
        break;

    case LEX_MOD:
        function = jsex_rt_modulo;
        break;

    default:
        return node;
    }

    ++(*tokens);
    sibling = jsex_parse_term(tokens);

    if (!sibling) {
        goto error;
    }

    parent = calloc(1, sizeof(jsex_t));
    parent->function = function;
    parent->args[0] = node;
    parent->args[1] = sibling;

    return parent;

error:
    jsex_free(node);
    return NULL;
}

// <factor> ::= '(' <query> ')' | '-' <factor> | <function> | <variable> | <float> | <integer> | <string> | 'null'
jsex_t * jsex_parse_factor(const jsex_token_t ** tokens) {
    jsex_t * node = NULL;
    jsex_t * parent;

    debug("jsex_parse_factor(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    switch ((*tokens)->type) {
    case LEX_LPAREN:
        ++(*tokens);
        node = jsex_parse_query(tokens);

        if (!node) {
            goto error;
        }

        if ((*tokens)->type != LEX_LPAREN) {
            error("Expected %s, got '%s'", TOKENS[LEX_LPAREN], (*tokens)->string);
            goto error;
        }

        ++(*tokens);
        break;

    case LEX_ID:
        if ((*tokens)[1].type == LEX_LPAREN) {
            node = jsex_parse_function(tokens);

            if (!node) {
                goto error;
            }
        } else if (strcmp((*tokens)->string, KEYWORD_NULL) == 0) {
            node = jsex_parse_null(tokens);

            if (!node) {
                goto error;
            }
        } else {
            node = jsex_parse_variable(tokens);

            if (!node) {
                goto error;
            }
        }

        break;

    case LEX_FLOAT:
        node = jsex_parse_float(tokens);

        if (!node) {
            goto error;
        }

        break;

    case LEX_INTEGER:
        node = jsex_parse_integer(tokens);

        if (!node) {
            goto error;
        }

        break;

    case LEX_STRING:
        node = jsex_parse_string(tokens);

        if (!node) {
            goto error;
        }

        break;

    case LEX_MINUS:
        ++(*tokens);

        node = jsex_parse_factor(tokens);

        if (!node) {
            goto error;
        }

        parent = calloc(1, sizeof(jsex_t));
        parent->function = jsex_rt_opposite;
        parent->args[0] = node;
        node = parent;

        break;

    default:
        error("Expected factor, got '%s'", (*tokens)->string);
        goto error;
    }

    return node;

error:
    jsex_free(node);
    return NULL;
}

// <function> ::= <id> '(' <query> ')'
jsex_t * jsex_parse_function(const jsex_token_t ** tokens) {
    jsex_t * node = NULL;

    debug("jsex_parse_function(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    if ((*tokens)->type != LEX_ID) {
        error("Expected %s, got '%s'", TOKENS[LEX_ID], (*tokens)->string);
        goto error;
    }

    node = calloc(1, sizeof(jsex_t));

    if (strcmp((*tokens)->string, FUNCTION_INT)) {
        node->function = jsex_rt_int;
    } else if (strcmp((*tokens)->string, FUNCTION_SIZE)) {
        node->function = jsex_rt_size;
    } else if (strcmp((*tokens)->string, FUNCTION_STRING)) {
        node->function = jsex_rt_string;
    } else {
        error("Invalid function");
        goto error;
    }

    ++(*tokens);

    if ((*tokens)->type != LEX_LPAREN) {
        error("Expected %s, got '%s'", TOKENS[LEX_LPAREN], (*tokens)->string);
        goto error;
    }

    ++(*tokens);
    node->args[0] = jsex_parse_query(tokens);

    if (!node->args[0]) {
        goto error;
    }

    if ((*tokens)->type != LEX_RPAREN) {
        error("Expected %s, got '%s'", TOKENS[LEX_RPAREN], (*tokens)->string);
        goto error;
    }

    ++(*tokens);
    return node;

error:
    jsex_free(node);
    return NULL;
}

// <variable> ::= <id> [ '[' <expression> ']' ] [ '.' <variable> ]
jsex_t * jsex_parse_variable(const jsex_token_t ** tokens) {
    jsex_t * node = NULL;
    jsex_t * index;
    jsex_t * parent;

    debug("jsex_parse_variable(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    if ((*tokens)->type != LEX_ID) {
        error("Expected %s, got '%s'", TOKENS[LEX_ID], (*tokens)->string);
        goto error;
    }

    node = calloc(1, sizeof(jsex_t));
    node->value = cJSON_CreateString((*tokens)->string);
    node->function = jsex_rt_variable;
    ++(*tokens);

    if ((*tokens)->type == LEX_LBRACKET) {
        ++(*tokens);

        index = jsex_parse_expression(tokens);

        if (!index) {
            goto error;
        }

        node->args[0] = index;

        if ((*tokens)->type != LEX_RBRACKET) {
            error("Expected %s, got '%s'", TOKENS[LEX_RBRACKET], (*tokens)->string);
            goto error;
        }

        ++(*tokens);
    }

    if ((*tokens)->type == LEX_DOT) {
        ++(*tokens);

        parent = jsex_parse_variable(tokens);

        if (!parent) {
            goto error;
        }

        parent->args[1] = node;
        node = parent;
    }

    return node;

error:
    jsex_free(node);
    return NULL;
}

// <loop> ::= ( 'all' | 'any' ) <id> 'in' <variable> ':' '(' <query> ')'
jsex_t * jsex_parse_loop(const jsex_token_t ** tokens) {
    jsex_t * node = NULL;

    debug("jsex_parse_loop(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    if ((*tokens)->type != LEX_ID) {
        error("Expected LEX_ID");
        goto error;
    }

    node = calloc(1, sizeof(jsex_t));

    if (strcmp((*tokens)->string, KEYWORD_ALL) == 0) {
        node->function = jsex_rt_loop_all;
    } else if (strcmp((*tokens)->string, KEYWORD_ANY) == 0) {
        node->function = jsex_rt_loop_any;
    } else {
        error("Expected '%s' or '%s', got '%s'", KEYWORD_ALL, KEYWORD_ANY, (*tokens)->string);
        goto error;
    }

    ++(*tokens);

    if ((*tokens)->type != LEX_ID) {
        error("Expected %s, got '%s'", TOKENS[LEX_ID], (*tokens)->string);
        goto error;
    }

    node->value = cJSON_CreateString((*tokens)->string);
    ++(*tokens);

    if (!((*tokens)->type == LEX_ID && strcmp((*tokens)->string, KEYWORD_IN) == 0)) {
        error("Expected '%s', got '%s'", KEYWORD_IN, (*tokens)->string);
        goto error;
    }

    ++(*tokens);
    node->args[0] = jsex_parse_variable(tokens);

    if (!node->args[0]) {
        goto error;
    }

    if ((*tokens)->type != LEX_COLON) {
        error("Expected %s, got '%s'", TOKENS[LEX_COLON], (*tokens)->string);
        goto error;
    }

    ++(*tokens);

    if ((*tokens)->type != LEX_LPAREN) {
        error("Expected %s, got '%s'", TOKENS[LEX_LPAREN], (*tokens)->string);
        goto error;
    }

    ++(*tokens);
    node->args[1] = jsex_parse_query(tokens);

    if (!node->args[1]) {
        goto error;
    }

    if ((*tokens)->type != LEX_RPAREN) {
        error("Expected %s, got '%s'", TOKENS[LEX_RPAREN], (*tokens)->string);
        goto error;
    }

    ++(*tokens);
    return node;

error:
    jsex_free(node);
    return NULL;
}

jsex_t * jsex_parse_null(const jsex_token_t ** tokens) {
    jsex_t * node;

    debug("jsex_parse_null(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    if (!((*tokens)->type == LEX_ID && strcmp((*tokens)->string, KEYWORD_NULL) == 0)) {
        error("Expected '%s', got '%s'", KEYWORD_NULL, (*tokens)->string);
        return NULL;
    }

    node = calloc(1, sizeof(jsex_t));
    node->value = cJSON_CreateNull();
    node->function = jsex_rt_value;
    ++(*tokens);
    return 0;
}

jsex_t * jsex_parse_float(const jsex_token_t ** tokens) {
    double number;
    char * end;
    jsex_t * node;

    debug("jsex_parse_float(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    if ((*tokens)->type != LEX_FLOAT) {
        error("Expected %s, got '%s'", TOKENS[LEX_FLOAT], (*tokens)->string);
        return NULL;
    }

    number = strtod((*tokens)->string, &end);

    if (end == (*tokens)->string) {
        error("Failed to parse '%s' into float.", (*tokens)->string);
        return NULL;
    }

    node = calloc(1, sizeof(jsex_t));
    node->value = cJSON_CreateNumber(number);
    node->function = jsex_rt_value;
    ++(*tokens);
    return node;
}

jsex_t * jsex_parse_integer(const jsex_token_t ** tokens) {
    int number;
    char *end;
    jsex_t * node;

    debug("jsex_parse_integer(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    if ((*tokens)->type != LEX_INTEGER) {
        error("Expected %s, got '%s'", TOKENS[LEX_INTEGER], (*tokens)->string);
        return NULL;
    }

    number = (int)strtol((*tokens)->string, &end, 10);

    if (end == (*tokens)->string) {
        error("Failed to parse '%s' into integer.", (*tokens)->string);
        return NULL;
    }

    node = calloc(1, sizeof(jsex_t));
    node->value = cJSON_CreateNumber(number);
    node->function = jsex_rt_value;
    ++(*tokens);
    return node;
}

jsex_t * jsex_parse_string(const jsex_token_t ** tokens) {
    char * string;
    char * escape;
    jsex_t * node;

    debug("jsex_parse_string(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    if ((*tokens)->type != LEX_STRING) {
        error("Expected %s, got '%s'", TOKENS[LEX_STRING], (*tokens)->string);
        return NULL;
    }

    // Duplicate string and remove quotes

    string = strdup((*tokens)->string + 1);
    string[strlen(string) - 1] = '\0';

    // Escape characters

    for (escape = string; escape = strchr(escape, '\\'), escape; ++escape) {
        strcpy(escape, escape + 1);
    }

    node = calloc(1, sizeof(jsex_t));
    node->value = cJSON_CreateString(string);
    node->regex = malloc(sizeof(regex_t));
    node->function = jsex_rt_value;

    if (regcomp(node->regex, string, REG_EXTENDED)) {
        debug("At jsex_parse_string(): not a regex.");
        free(node->regex);
        node->regex = NULL;
    }

    ++(*tokens);
    free(string);
    return node;
}

/* Runtime functions **********************************************************/

void jsex_rt_and(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON result_p[2] = { CJSON_INITIALIZER, CJSON_INITIALIZER };

    node->args[0]->function(node->args[0], value, &result_p[0]);
    node->args[1]->function(node->args[1], value, &result_p[1]);
    result->type = result_p[0].type == cJSON_True && result_p[1].type == cJSON_True ? cJSON_True : cJSON_False;
}

void jsex_rt_or(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON result_p[2] = { CJSON_INITIALIZER, CJSON_INITIALIZER };

    node->args[0]->function(node->args[0], value, &result_p[0]);
    node->args[1]->function(node->args[1], value, &result_p[1]);
    result->type = result_p[0].type == cJSON_True || result_p[1].type == cJSON_True ? cJSON_True : cJSON_False;
}

void jsex_rt_match(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON result_p = CJSON_INITIALIZER;

    node->args[0]->function(node->args[0], value, &result_p);
    // node->args[1] should be a string literal, with corresponding regex

    if (result_p.type == cJSON_String && node->args[1]->regex) {
        result-> type = regexec(node->args[1]->regex, result_p.valuestring, 0, NULL, 0) ? cJSON_False : cJSON_True;
    } else {
        result->type = cJSON_NULL;
    }
}

void jsex_rt_equal(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON result_p[2] = { CJSON_INITIALIZER, CJSON_INITIALIZER };

    node->args[0]->function(node->args[0], value, &result_p[0]);
    node->args[1]->function(node->args[1], value, &result_p[1]);

    if (result_p[0].type == cJSON_Number && result_p[1].type == cJSON_Number) {
        result->type = result_p[0].valuedouble < result_p[1].valuedouble ? cJSON_True : cJSON_False;
    } else if (result_p[0].type == cJSON_String && result_p[1].type == cJSON_String) {
        result->type = strcmp(result_p[0].valuestring, result_p[1].valuestring) ? cJSON_False : cJSON_True;
    } else {
        result->type = cJSON_NULL;
    }
}

void jsex_rt_not_equal(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON result_p[2] = { CJSON_INITIALIZER, CJSON_INITIALIZER };

    node->args[0]->function(node->args[0], value, &result_p[0]);
    node->args[1]->function(node->args[1], value, &result_p[1]);

    if (result_p[0].type == cJSON_Number && result_p[1].type == cJSON_Number) {
        result->type = result_p[0].valuedouble < result_p[1].valuedouble ? cJSON_False : cJSON_True;
    } else if (result_p[0].type == cJSON_String && result_p[1].type == cJSON_String) {
        result->type = strcmp(result_p[0].valuestring, result_p[1].valuestring) ? cJSON_True : cJSON_False;
    } else {
        result->type = cJSON_NULL;
    }
}

void jsex_rt_greater_equal(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON result_p[2] = { CJSON_INITIALIZER, CJSON_INITIALIZER };

    node->args[0]->function(node->args[0], value, &result_p[0]);
    node->args[1]->function(node->args[1], value, &result_p[1]);

    if (result_p[0].type == cJSON_Number && result_p[1].type == cJSON_Number) {
        result->type = result_p[0].valuedouble >= result_p[1].valuedouble ? cJSON_True : cJSON_False;
    } else {
        result->type = cJSON_NULL;
    }
}

void jsex_rt_less_equal(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON result_p[2] = { CJSON_INITIALIZER, CJSON_INITIALIZER };

    node->args[0]->function(node->args[0], value, &result_p[0]);
    node->args[1]->function(node->args[1], value, &result_p[1]);

    if (result_p[0].type == cJSON_Number && result_p[1].type == cJSON_Number) {
        result->type = result_p[0].valuedouble <= result_p[1].valuedouble ? cJSON_True : cJSON_False;
    } else {
        result->type = cJSON_NULL;
    }
}

void jsex_rt_greater(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON result_p[2] = { CJSON_INITIALIZER, CJSON_INITIALIZER };

    node->args[0]->function(node->args[0], value, &result_p[0]);
    node->args[1]->function(node->args[1], value, &result_p[1]);

    if (result_p[0].type == cJSON_Number && result_p[1].type == cJSON_Number) {
        result->type = result_p[0].valuedouble > result_p[1].valuedouble ? cJSON_True : cJSON_False;
    } else {
        result->type = cJSON_NULL;
    }
}

void jsex_rt_less(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON result_p[2] = { CJSON_INITIALIZER, CJSON_INITIALIZER };

    node->args[0]->function(node->args[0], value, &result_p[0]);
    node->args[1]->function(node->args[1], value, &result_p[1]);

    if (result_p[0].type == cJSON_Number && result_p[1].type == cJSON_Number) {
        result->type = result_p[0].valuedouble < result_p[1].valuedouble ? cJSON_True : cJSON_False;
    } else {
        result->type = cJSON_NULL;
    }
}

void jsex_rt_add(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON result_p[2] = { CJSON_INITIALIZER, CJSON_INITIALIZER };

    node->args[0]->function(node->args[0], value, &result_p[0]);
    node->args[1]->function(node->args[1], value, &result_p[1]);

    if (result_p[0].type == cJSON_Number && result_p[1].type == cJSON_Number) {
        result->type = cJSON_Number;
        cJSON_SetNumberValue(result, result_p[0].valuedouble + result_p[1].valuedouble);
    } else {
        result->type = cJSON_NULL;
    }
}

void jsex_rt_subtract(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON result_p[2] = { CJSON_INITIALIZER, CJSON_INITIALIZER };

    node->args[0]->function(node->args[0], value, &result_p[0]);
    node->args[1]->function(node->args[1], value, &result_p[1]);

    if (result_p[0].type == cJSON_Number && result_p[1].type == cJSON_Number) {
        result->type = cJSON_Number;
        cJSON_SetNumberValue(result, result_p[0].valuedouble - result_p[1].valuedouble);
    } else {
        result->type = cJSON_NULL;
    }
}

void jsex_rt_multiply(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON result_p[2] = { CJSON_INITIALIZER, CJSON_INITIALIZER };

    node->args[0]->function(node->args[0], value, &result_p[0]);
    node->args[1]->function(node->args[1], value, &result_p[1]);

    if (result_p[0].type == cJSON_Number && result_p[1].type == cJSON_Number) {
        result->type = cJSON_Number;
        cJSON_SetNumberValue(result, result_p[0].valuedouble * result_p[1].valuedouble);
    } else {
        result->type = cJSON_NULL;
    }
}

void jsex_rt_divide(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON result_p[2] = { CJSON_INITIALIZER, CJSON_INITIALIZER };

    node->args[0]->function(node->args[0], value, &result_p[0]);
    node->args[1]->function(node->args[1], value, &result_p[1]);

    if (result_p[0].type == cJSON_Number && result_p[1].type == cJSON_Number && result_p[1].valuedouble != 0) {
        result->type = cJSON_Number;
        cJSON_SetNumberValue(result, result_p[0].valuedouble / result_p[1].valuedouble);
    } else {
        result->type = cJSON_NULL;
    }
}

void jsex_rt_modulo(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON result_p[2] = { CJSON_INITIALIZER, CJSON_INITIALIZER };

    node->args[0]->function(node->args[0], value, &result_p[0]);
    node->args[1]->function(node->args[1], value, &result_p[1]);

    if (result_p[0].type == cJSON_Number && result_p[1].type == cJSON_Number && result_p[1].valueint != 0) {
        result->type = cJSON_Number;
        cJSON_SetNumberValue(result, (int)(result_p[0].valueint % result_p[1].valueint));
    } else {
        result->type = cJSON_NULL;
    }
}

void jsex_rt_negate(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON result_p = CJSON_INITIALIZER;

    node->args[0]->function(node->args[0], value, &result_p);

    switch (result_p.type) {
    case cJSON_False:
        result->type = cJSON_True;
        break;

    case cJSON_True:
        result->type = cJSON_False;
        break;

    default:
        result->type = cJSON_NULL;
    }
}

void jsex_rt_opposite(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON result_p = CJSON_INITIALIZER;

    node->args[0]->function(node->args[0], value, &result_p);

    if (result_p.type == cJSON_Number) {
        result->type = cJSON_Number;
        cJSON_SetNumberValue(result, -result_p.valuedouble);
    } else {
        result->type = cJSON_NULL;
    }
}

void jsex_rt_int(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON result_p = CJSON_INITIALIZER;

    node->args[0]->function(node->args[0], value, &result_p);
    result->type = cJSON_Number;
    cJSON_SetNumberValue(result, jsex_cast_int(&result_p));
}

void jsex_rt_size(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON result_p = CJSON_INITIALIZER;

    node->args[0]->function(node->args[0], value, &result_p);
    result->type = cJSON_Number;
    cJSON_SetNumberValue(result, cJSON_GetArraySize(&result_p));
}

void jsex_rt_string(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON result_p = CJSON_INITIALIZER;
    char *string = "";
    char buffer[64];

    node->args[0]->function(node->args[0], value, &result_p);

    switch (result_p.type) {
    case cJSON_Invalid:
        break;

    case cJSON_False:
        string = "false";
        break;

    case cJSON_True:
        string = "true";
        break;

    case cJSON_NULL:
        string = "null";
        break;

    case cJSON_Number:
        snprintf(buffer, 64, "%f", value->valuedouble);
        string = buffer;
        break;

    case cJSON_String:
        string = result_p.valuestring;
        break;

    case cJSON_Array:
    case cJSON_Object:
        break;

    case cJSON_Raw:
        string = result_p.valuestring;
        break;

    default:
        debug("At jsex_rt_string(): unknown value type (%d)", result_p.type);
    }

    result->type = cJSON_String;
    result->valuestring = strdup(string);
}

void jsex_rt_variable(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON index = CJSON_INITIALIZER;
    cJSON parent = CJSON_INITIALIZER;
    const cJSON * result_p;

    // Optional child node (left part of the member)

    if (node->args[1]) {
        node->args[1]->function(node->args[1], value, &parent);
        result_p = &parent;
    } else {
        result_p = value;
    }

    result_p = cJSON_GetObjectItem(result_p, node->value->valuestring);

    if (!result_p) {
        result->type = cJSON_NULL;
        return;
    }

    if (node->args[0]) {
        node->args[0]->function(node->args[0], value, &index);
        result_p = index.type == cJSON_Number ? cJSON_GetArrayItem(value, node->value->valueint) : NULL;

        if (!result_p) {
            result->type = cJSON_NULL;
            return;
        }
    }

    memcpy(result, result_p, sizeof(cJSON));
}

void jsex_rt_loop_all(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON array = CJSON_INITIALIZER;
    cJSON result_p = CJSON_INITIALIZER;
    cJSON * element;
    cJSON * root;

    node->args[0]->function(node->args[0], value, &array);

    // If size == 0, return False

    if (!array.child) {
        result->type = cJSON_False;
        return;
    }

    cJSON_ArrayForEach(element, &array) {
        root = cJSON_CreateObject();
        // TODO: Ain't sure...
        cJSON_AddItemReferenceToObject(root, node->value->valuestring, element);

        node->args[1]->function(node->args[1], root, &result_p);
        cJSON_Delete(root);

        if (!jsex_cast_bool(&result_p)) {
            result->type = cJSON_False;
            return;
        }
    }

    result->type = cJSON_True;
}

void jsex_rt_loop_any(const jsex_t * node, const cJSON * value, cJSON * result) {
    cJSON array = CJSON_INITIALIZER;
    cJSON result_p = CJSON_INITIALIZER;
    cJSON * element;
    cJSON * root;

    node->args[0]->function(node->args[0], value, &array);

    cJSON_ArrayForEach(element, &array) {
        root = cJSON_CreateObject();
        // TODO: Ain't sure...
        cJSON_AddItemReferenceToObject(root, node->value->valuestring, element);

        node->args[1]->function(node->args[1], root, &result_p);
        cJSON_Delete(root);

        if (jsex_cast_bool(&result_p)) {
            result->type = cJSON_True;
            return;
        }
    }

    result->type = cJSON_False;
}

void jsex_rt_value(const jsex_t * node, __attribute__((unused)) const cJSON * value, cJSON * result) {
    memcpy(result, node->value, sizeof(cJSON));
}

/* Helper runtime functions ***************************************************/

int jsex_cast_bool(const cJSON * value) {
    switch (value->type) {
    case cJSON_Invalid:
    case cJSON_False:
        return 0;
    case cJSON_True:
        return 1;
    case cJSON_NULL:
        return 0;
    case cJSON_Number:
        return value->valueint != 0;
    case cJSON_String:
        return *value->valuestring != '\0';
    case cJSON_Array:
    case cJSON_Object:
        return value->child != NULL;
    case cJSON_Raw:
        return value->valuestring != '\0';
    default:
        debug("At jsex_cast_bool(): unknown value type (%d)", value->type);
        return 0;
    }
}

int jsex_cast_int(const cJSON * value) {
    int number;
    char * end;
    cJSON * child;

    switch (value->type) {
    case cJSON_Invalid:
    case cJSON_False:
        return 0;

    case cJSON_True:
        return 1;

    case cJSON_NULL:
        return 0;

    case cJSON_Number:
        return value->valueint;

    case cJSON_String:
        number = (int)strtol(value->valuestring, &end, 10);
        return end != value->valuestring ? number : 0;

    case cJSON_Array:
    case cJSON_Object:
        return ((child = value->child) && !child->next) ? jsex_cast_int(child) : 0;

    case cJSON_Raw:
        return 0;

    default:
        debug("At jsex_cast_int(): unknown value type (%d)", value->type);
        return 0;
    }
}
