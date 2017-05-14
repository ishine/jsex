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
  #ifndef NODEBUG_LEXER
    #define debug_lexer debug
  #else
    #define debug_lexer(format, ...)
  #endif
  #ifndef NODEBUG_PARSER
    #define debug_parser debug
  #else
    #define debug_parser(format, ...)
  #endif
  #ifndef NODEBUG_RT
    #define debug_rt debug
  #else
    #define debug_rt(format, ...)
  #endif
#else
  #define debug(format, ...)
  #define debug_lexer(format, ...)
  #define debug_parser(format, ...)
  #define debug_rt(format, ...)
#endif

#ifdef PROFILE
  #include <time.h>
  #define profile_start() clock_t clock_s = clock()
  #define profile_reset() clock_s = clock()
  #define profile_print(name) printf("PROFILE: " name ": %.0f µs.\n", (double)(clock() - clock_s) * 1000000 / CLOCKS_PER_SEC)
#else
  #define profile_start()
  #define profile_reset()
  #define profile_print(name)
#endif

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
    "^\"(\\\\\"|[^\"])*\"|^'(\\\\'|[^'])*'",
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
static const char * const FUNCTION_BOOL = "bool";
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
static jsex_t * jsex_parse_member(const jsex_token_t ** tokens);
static jsex_t * jsex_parse_root(const jsex_token_t ** tokens);
static jsex_t * jsex_parse_loop(const jsex_token_t ** tokens);
static jsex_t * jsex_parse_null(const jsex_token_t ** tokens);
static jsex_t * jsex_parse_float(const jsex_token_t ** tokens);
static jsex_t * jsex_parse_integer(const jsex_token_t ** tokens);
static jsex_t * jsex_parse_string(const jsex_token_t ** tokens);

static cJSON * jsex_rt_and(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_or(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_match(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_equal(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_not_equal(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_greater_equal(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_less_equal(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_greater(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_less(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_add(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_subtract(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_multiply(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_divide(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_modulo(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_negate(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_opposite(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_int(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_size(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_string(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_bool(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_variable(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_index(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_loop_all(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_loop_any(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_root(const jsex_t * node, const cJSON * value);
static cJSON * jsex_rt_value(const jsex_t * node, const cJSON * value);

static cJSON * jsex_cast_bool(const cJSON * value);
static cJSON * jsex_cast_int(const cJSON * value);
static cJSON * jsex_cast_string(const cJSON * value);

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

cJSON * jsex_exec(const jsex_t * node, cJSON * value) {
    cJSON * result;

    profile_start();
    result = node->function(node, value);
    profile_print("jsex_exec()");
    return result;
}

int jsex_test(const jsex_t * node, cJSON * value) {
    int retval;
    cJSON * result;
    cJSON * temp;

    profile_start();
    temp = node->function(node, value);
    result = jsex_cast_bool(temp);
    retval = cJSON_IsTrue(result);
    cJSON_Delete(temp);
    cJSON_Delete(result);
    profile_print("jsex_test()");
    return retval;
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
    debug_lexer("jsex_lexer(): %s", input);

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
        debug_lexer("jsex_lexer_next(): [%s]", TOKENS[LEX_NONE]);
        *offset = 0;
        return LEX_NONE;
    }

    for (i = 0; i < N_PATTERNS; i++) {
        errcode = regexec(regexes + i, input, 1, &match, 0);

        switch (errcode) {
        case 0:
            *offset = match.rm_eo;

            if (i > 0) {
                debug_lexer("jsex_lexer_next(): [%s] %.*s", TOKENS[i], (int)match.rm_eo, input);
            }

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
    cJSON * (* function)(const jsex_t *, const cJSON *);

    debug_parser("jsex_parse_query(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

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
    cJSON * (* function)(const jsex_t *, const cJSON *);

    debug_parser("jsex_parse_sentence(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

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
    cJSON * (* function)(const jsex_t *, const cJSON *);

    debug_parser("jsex_parse_expression(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

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
    cJSON * (* function)(const jsex_t *, const cJSON *);

    debug_parser("jsex_parse_term(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

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

    debug_parser("jsex_parse_factor(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    switch ((*tokens)->type) {
    case LEX_LPAREN:
        ++(*tokens);
        node = jsex_parse_query(tokens);

        if (!node) {
            goto error;
        }

        if ((*tokens)->type != LEX_RPAREN) {
            error("Expected %s, got '%s'", TOKENS[LEX_RPAREN], (*tokens)->string);
            goto error;
        }

        ++(*tokens);
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
            node = jsex_parse_member(tokens);

            if (!node) {
                goto error;
            }
        }

        break;

    case LEX_STRING:
        node = jsex_parse_string(tokens);

        if (!node) {
            goto error;
        }

        break;

    case LEX_DOT:
        node = jsex_parse_root(tokens);

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

    debug_parser("jsex_parse_function(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    if ((*tokens)->type != LEX_ID) {
        error("Expected %s, got '%s'", TOKENS[LEX_ID], (*tokens)->string);
        goto error;
    }

    node = calloc(1, sizeof(jsex_t));

    if (strcmp((*tokens)->string, FUNCTION_INT) == 0) {
        node->function = jsex_rt_int;
    } else if (strcmp((*tokens)->string, FUNCTION_SIZE) == 0) {
        node->function = jsex_rt_size;
    } else if (strcmp((*tokens)->string, FUNCTION_STRING) == 0) {
        node->function = jsex_rt_string;
    } else if (strcmp((*tokens)->string, FUNCTION_BOOL) == 0) {
        node->function = jsex_rt_bool;
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


// <variable> ::= <member> | <root>
jsex_t * jsex_parse_variable(const jsex_token_t ** tokens) {
    switch ((*tokens)->type) {
    case LEX_ID:
        return jsex_parse_member(tokens);

    case LEX_DOT:
        return jsex_parse_root(tokens);

    default:
        error("Expected variable, got '%s'", (*tokens)->string);
        return NULL;
    }
}

// <member> ::= <id> ( '[' <expression> ']' )* [ '.' <member> ]
jsex_t * jsex_parse_member(const jsex_token_t ** tokens) {
    jsex_t * node = NULL;
    jsex_t * index;
    jsex_t * parent;

    debug_parser("jsex_parse_member(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    if ((*tokens)->type != LEX_ID) {
        error("Expected %s, got '%s'", TOKENS[LEX_ID], (*tokens)->string);
        goto error;
    }

    node = calloc(1, sizeof(jsex_t));
    node->value = cJSON_CreateString((*tokens)->string);
    node->function = jsex_rt_variable;
    ++(*tokens);

    while ((*tokens)->type == LEX_LBRACKET) {
        ++(*tokens);

        index = jsex_parse_expression(tokens);

        if (!index) {
            goto error;
        }

        parent = calloc(1, sizeof(jsex_t));
        parent->args[0] = node;
        parent->args[1] = index;
        parent->function = jsex_rt_index;
        node = parent;

        if ((*tokens)->type != LEX_RBRACKET) {
            error("Expected %s, got '%s'", TOKENS[LEX_RBRACKET], (*tokens)->string);
            goto error;
        }

        ++(*tokens);
    }

    if ((*tokens)->type == LEX_DOT) {
        ++(*tokens);

        parent = jsex_parse_member(tokens);

        if (!parent) {
            goto error;
        }

        parent->args[0] = node;
        node = parent;
    }

    return node;

error:
    jsex_free(node);
    return NULL;
}

// <root> ::= '.' [ ( '[' <expression> ']' )+ [ '.' <member> ] | <member> ]
jsex_t * jsex_parse_root(const jsex_token_t ** tokens) {
    jsex_t * node = NULL;
    jsex_t * index;
    jsex_t * parent;

    debug_parser("jsex_parse_root(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    if ((*tokens)->type != LEX_DOT) {
        error("Expected %s, got '%s'", TOKENS[LEX_DOT], (*tokens)->string);
        goto error;
    }

    ++(*tokens);

    switch ((*tokens)->type) {
    case LEX_LBRACKET:
        ++(*tokens);

        index = jsex_parse_expression(tokens);

        if (!index) {
            goto error;
        }

        node = calloc(1, sizeof(jsex_t));
        node->args[1] = index;
        node->function = jsex_rt_index;

        if ((*tokens)->type != LEX_RBRACKET) {
            error("Expected %s, got '%s'", TOKENS[LEX_RBRACKET], (*tokens)->string);
            goto error;
        }

        ++(*tokens);

        while ((*tokens)->type == LEX_LBRACKET) {
            ++(*tokens);

            index = jsex_parse_expression(tokens);

            if (!index) {
                goto error;
            }

            parent = calloc(1, sizeof(jsex_t));
            parent->args[0] = node;
            parent->args[1] = index;
            parent->function = jsex_rt_index;
            node = parent;

            if ((*tokens)->type != LEX_RBRACKET) {
                error("Expected %s, got '%s'", TOKENS[LEX_RBRACKET], (*tokens)->string);
                goto error;
            }

            ++(*tokens);
        }

        if ((*tokens)->type == LEX_DOT) {
            ++(*tokens);

            parent = jsex_parse_member(tokens);

            if (!parent) {
                goto error;
            }

            parent->args[0] = node;
            node = parent;
        }

        break;

    case LEX_ID:
        node = jsex_parse_member(tokens);

        if (!node) {
            goto error;
        }

        break;

    default:
        node = calloc(1, sizeof(jsex_t));
        node->function = jsex_rt_root;
    }

    return node;

error:
    jsex_free(node);
    return NULL;
}

// <loop> ::= ( 'all' | 'any' ) <id> 'in' <variable> ':' '(' <query> ')'
jsex_t * jsex_parse_loop(const jsex_token_t ** tokens) {
    jsex_t * node = NULL;

    debug_parser("jsex_parse_loop(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

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

    debug_parser("jsex_parse_null(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

    if (!((*tokens)->type == LEX_ID && strcmp((*tokens)->string, KEYWORD_NULL) == 0)) {
        error("Expected '%s', got '%s'", KEYWORD_NULL, (*tokens)->string);
        return NULL;
    }

    node = calloc(1, sizeof(jsex_t));
    node->value = cJSON_CreateNull();
    node->function = jsex_rt_value;
    ++(*tokens);
    return node;;
}

jsex_t * jsex_parse_float(const jsex_token_t ** tokens) {
    double number;
    char * end;
    jsex_t * node;

    debug_parser("jsex_parse_float(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

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

    debug_parser("jsex_parse_integer(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

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

    debug_parser("jsex_parse_string(): [%s] %s", TOKENS[(*tokens)->type], (*tokens)->string);

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

cJSON * jsex_rt_and(const jsex_t * node, const cJSON * value) {
    cJSON * result = node->args[0]->function(node->args[0], value);
    cJSON * temp;

    switch (result->type) {
    case cJSON_False:
        debug_rt("jsex_rt: (false && ) -> false");
        break;

    case cJSON_True:
        temp = node->args[1]->function(node->args[1], value);

        switch (temp->type) {
        case cJSON_False:
            result->type = cJSON_False;
            debug_rt("jsex_rt: (true && false) -> false");
            break;

        case cJSON_True:
            debug_rt("jsex_rt: (true && true) -> true");
            break;

        default:
            debug_rt("jsex_rt: (true && ) -> null");
            cJSON_Delete(result);
            result = cJSON_CreateNull();
        }

        cJSON_Delete(temp);
        break;

    default:
        debug_rt("jsex_rt: ( && ) -> null");
        cJSON_Delete(result);
        result = cJSON_CreateNull();

    }

    return result;
}

cJSON * jsex_rt_or(const jsex_t * node, const cJSON * value) {
    cJSON * result = node->args[0]->function(node->args[0], value);
    cJSON * temp;

    switch (result->type) {
    case cJSON_False:
        temp = node->args[1]->function(node->args[1], value);

        switch (temp->type) {
        case cJSON_False:
            debug_rt("jsex_rt: (false || false) -> false");
            break;

        case cJSON_True:
            result->type = cJSON_True;
            debug_rt("jsex_rt: (false || true) -> true");
            break;

        default:
            debug_rt("jsex_rt: (false && ) -> null");
            cJSON_Delete(result);
            result = cJSON_CreateNull();
        }

        cJSON_Delete(temp);
        break;

    case cJSON_True:
        debug_rt("jsex_rt: (true && ) -> true");
        break;

    default:
        debug_rt("jsex_rt: ( && ) -> null");
        cJSON_Delete(result);
        result = cJSON_CreateNull();

    }

    return result;
}

cJSON * jsex_rt_match(const jsex_t * node, const cJSON * value) {
    cJSON * left;
    cJSON * result;

    // node->args[1] should be a string literal, with corresponding regex

    if (node->args[1]->regex) {
        left = node->args[0]->function(node->args[0], value);

        if (cJSON_IsString(left)) {
            result = cJSON_CreateBool(regexec(node->args[1]->regex, left->valuestring, 0, NULL, 0) == 0);
            debug_rt("jsex_rt: ('%s' =~ '%s') -> %s", left->valuestring, node->args[1]->value->valuestring, cJSON_IsTrue(result) ? "true" : "false");
        } else {
            result = cJSON_CreateNull();
            debug_rt("jsex_rt: ( =~ '%s') -> null", node->args[1]->value->valuestring);
        }

        cJSON_Delete(left);

    } else {
        result = cJSON_CreateNull();
        debug_rt("jsex_rt: ( =~ ) -> null");
    }

    return result;
}

cJSON * jsex_rt_equal(const jsex_t * node, const cJSON * value) {
    cJSON * left = node->args[0]->function(node->args[0], value);
    cJSON * right = node->args[1]->function(node->args[1], value);
    cJSON * result;

    switch (left->type) {
    case cJSON_False:
        switch (right->type) {
        case cJSON_False:
            result = cJSON_CreateTrue();
            debug_rt("jsex_rt: (false == false) -> true");
            break;

        case cJSON_True:
            result = cJSON_CreateFalse();
            debug_rt("jsex_rt: (false == true) -> false");
            break;

        case cJSON_NULL:
            result = cJSON_CreateFalse();
            debug_rt("jsex_rt: (false == null) -> false");
            break;

        default:
            debug_rt("jsex_rt: (false == ) -> null");
            result = cJSON_CreateNull();
        }

        break;

    case cJSON_True:
        switch (right->type) {
        case cJSON_False:
            result = cJSON_CreateFalse();
            debug_rt("jsex_rt: (true == false) -> false");
            break;

        case cJSON_True:
            result = cJSON_CreateTrue();
            debug_rt("jsex_rt: (true == true) -> true");
            break;

        case cJSON_NULL:
            result = cJSON_CreateFalse();
            debug_rt("jsex_rt: (true == null) -> false");
            break;

        default:
            result = cJSON_CreateNull();
            debug_rt("jsex_rt: (true == ) -> null");
        }

        break;

    case cJSON_NULL:
        if (cJSON_IsNull(right)) {
            result = cJSON_CreateTrue();
            debug_rt("jsex_rt: (null == null) -> true");
        } else {
            result = cJSON_CreateFalse();
            debug_rt("jsex_rt: (null == ) -> false");
        }

        break;

    case cJSON_Number:
        switch (right->type) {
        case cJSON_NULL:
            result = cJSON_CreateFalse();
            debug_rt("jsex_rt: (%f == null) -> false", left->valuedouble);
            break;

        case cJSON_Number:
            result = cJSON_CreateBool(left->valuedouble == right->valuedouble);
            debug_rt("jsex_rt: (%f == %f) -> %s", left->valuedouble, right->valuedouble, cJSON_IsTrue(result) ? "true" : "false");
            break;

        default:
            result = cJSON_CreateNull();
            debug_rt("jsex_rt: (%f == ) -> null", left->valuedouble);
        }

        break;

    case cJSON_String:
        switch (right->type) {
        case cJSON_NULL:
            result = cJSON_CreateFalse();
            debug_rt("jsex_rt: (%s == null) -> false", left->valuestring);
            break;

        case cJSON_String:
            result = cJSON_CreateBool(strcmp(left->valuestring, right->valuestring) == 0);
            debug_rt("jsex_rt: (%s == %s) -> %s", left->valuestring, right->valuestring, cJSON_IsTrue(result) ? "true" : "false");
            break;

        default:
            result = cJSON_CreateNull();
            debug_rt("jsex_rt: (%s == ) -> null", left->valuestring);
        }

        break;

    default:
        result = cJSON_CreateNull();
        debug_rt("jsex_rt: ( == ) -> null");
    }

    cJSON_Delete(left);
    cJSON_Delete(right);
    return result;
}

cJSON * jsex_rt_not_equal(const jsex_t * node, const cJSON * value) {
    cJSON * left = node->args[0]->function(node->args[0], value);
    cJSON * right = node->args[1]->function(node->args[1], value);
    cJSON * result;

    switch (left->type) {
    case cJSON_False:
        switch (right->type) {
        case cJSON_False:
            result = cJSON_CreateFalse();
            debug_rt("jsex_rt: (false != false) -> false");
            break;

        case cJSON_True:
            result = cJSON_CreateTrue();
            debug_rt("jsex_rt: (false != true) -> true");
            break;

        case cJSON_NULL:
            result = cJSON_CreateTrue();
            debug_rt("jsex_rt: (false != null) -> true");
            break;

        default:
            debug_rt("jsex_rt: (false != ) -> null");
            result = cJSON_CreateNull();
        }

        break;

    case cJSON_True:
        switch (right->type) {
        case cJSON_False:
            result = cJSON_CreateTrue();
            debug_rt("jsex_rt: (true != false) -> true");
            break;

        case cJSON_True:
            result = cJSON_CreateFalse();
            debug_rt("jsex_rt: (true != true) -> false");
            break;

        case cJSON_NULL:
            result = cJSON_CreateTrue();
            debug_rt("jsex_rt: (true != null) -> true");
            break;

        default:
            result = cJSON_CreateNull();
            debug_rt("jsex_rt: (true != ) -> null");
        }

        break;

    case cJSON_NULL:
        if (cJSON_IsNull(right)) {
            result = cJSON_CreateFalse();
            debug_rt("jsex_rt: (null != null) -> false");
        } else {
            result = cJSON_CreateTrue();
            debug_rt("jsex_rt: (null != ) -> true");
        }

        break;

    case cJSON_Number:
        switch (right->type) {
        case cJSON_NULL:
            result = cJSON_CreateTrue();
            debug_rt("jsex_rt: (%f != null) -> true", left->valuedouble);
            break;

        case cJSON_Number:
            result = cJSON_CreateBool(left->valuedouble != right->valuedouble);
            debug_rt("jsex_rt: (%f != %f) -> %s", left->valuedouble, right->valuedouble, cJSON_IsTrue(result) ? "true" : "false");
            break;

        default:
            result = cJSON_CreateNull();
            debug_rt("jsex_rt: (%f != ) -> null", left->valuedouble);
        }

        break;

    case cJSON_String:
        switch (right->type) {
        case cJSON_NULL:
            result = cJSON_CreateTrue();
            debug_rt("jsex_rt: (%s != null) -> true", left->valuestring);
            break;

        case cJSON_String:
            result = cJSON_CreateBool(strcmp(left->valuestring, right->valuestring) != 0);
            debug_rt("jsex_rt: (%s != %s) -> %s", left->valuestring, right->valuestring, cJSON_IsTrue(result) ? "true" : "false");
            break;

        default:
            result = cJSON_CreateNull();
            debug_rt("jsex_rt: (%s != ) -> null", left->valuestring);
        }

        break;

    default:
        result = cJSON_CreateNull();
        debug_rt("jsex_rt: ( != ) -> null");
    }

    cJSON_Delete(left);
    cJSON_Delete(right);
    return result;
}

cJSON * jsex_rt_greater_equal(const jsex_t * node, const cJSON * value) {
    cJSON * left = node->args[0]->function(node->args[0], value);
    cJSON * right;
    cJSON * result;

    if (cJSON_IsNumber(left)) {
        right = node->args[1]->function(node->args[1], value);

        if (cJSON_IsNumber(right)) {
            result = cJSON_CreateBool(left->valuedouble >= right->valuedouble);
            debug_rt("jsex_rt: (%f >= %f) -> %s", left->valuedouble, right->valuedouble, cJSON_IsTrue(result) ? "true" : "false");
        } else {
            result = cJSON_CreateNull();
            debug_rt("jsex_rt: (%f >= ) -> null", left->valuedouble);
        }

        cJSON_Delete(right);
    } else {
        debug_rt("jsex_rt: ( >= ) -> null");
        result = cJSON_CreateNull();
    }

    cJSON_Delete(left);
    return result;
}

cJSON * jsex_rt_less_equal(const jsex_t * node, const cJSON * value) {
    cJSON * left = node->args[0]->function(node->args[0], value);
    cJSON * right;
    cJSON * result;

    if (cJSON_IsNumber(left)) {
        right = node->args[1]->function(node->args[1], value);

        if (cJSON_IsNumber(right)) {
            result = cJSON_CreateBool(left->valuedouble <= right->valuedouble);
            debug_rt("jsex_rt: (%f <= %f) -> %s", left->valuedouble, right->valuedouble, cJSON_IsTrue(result) ? "true" : "false");
        } else {
            result = cJSON_CreateNull();
            debug_rt("jsex_rt: (%f <= ) -> null", left->valuedouble);
        }

        cJSON_Delete(right);
    } else {
        debug_rt("jsex_rt: ( <= ) -> null");
        result = cJSON_CreateNull();
    }

    cJSON_Delete(left);
    return result;
}

cJSON * jsex_rt_greater(const jsex_t * node, const cJSON * value) {
    cJSON * left = node->args[0]->function(node->args[0], value);
    cJSON * right;
    cJSON * result;

    if (cJSON_IsNumber(left)) {
        right = node->args[1]->function(node->args[1], value);

        if (cJSON_IsNumber(right)) {
            result = cJSON_CreateBool(left->valuedouble > right->valuedouble);
            debug_rt("jsex_rt: (%f > %f) -> %s", left->valuedouble, right->valuedouble, cJSON_IsTrue(result) ? "true" : "false");
        } else {
            result = cJSON_CreateNull();
            debug_rt("jsex_rt: (%f > ) -> null", left->valuedouble);
        }

        cJSON_Delete(right);
    } else {
        debug_rt("jsex_rt: ( > ) -> null");
        result = cJSON_CreateNull();
    }

    cJSON_Delete(left);
    return result;
}

cJSON * jsex_rt_less(const jsex_t * node, const cJSON * value) {
    cJSON * left = node->args[0]->function(node->args[0], value);
    cJSON * right;
    cJSON * result;

    if (cJSON_IsNumber(left)) {
        right = node->args[1]->function(node->args[1], value);

        if (cJSON_IsNumber(right)) {
            result = cJSON_CreateBool(left->valuedouble < right->valuedouble);
            debug_rt("jsex_rt: (%f < %f) -> %s", left->valuedouble, right->valuedouble, cJSON_IsTrue(result) ? "true" : "false");
        } else {
            result = cJSON_CreateNull();
            debug_rt("jsex_rt: (%f < ) -> null", left->valuedouble);
        }

        cJSON_Delete(right);
    } else {
        debug_rt("jsex_rt: ( < ) -> null");
        result = cJSON_CreateNull();
    }

    cJSON_Delete(left);
    return result;
}

cJSON * jsex_rt_add(const jsex_t * node, const cJSON * value) {
    cJSON * result = node->args[0]->function(node->args[0], value);
    cJSON * aux;
    double number;
    char * string;
    size_t offset;

    switch (result->type) {
    case cJSON_Number:
        aux = node->args[1]->function(node->args[1], value);

        if (cJSON_IsNumber(aux)) {
            number = result->valuedouble + aux->valuedouble;
            debug_rt("jsex_rt: (%f + %f) -> %f", result->valuedouble, aux->valuedouble, number);
            cJSON_SetNumberValue(result, number);
        } else {
            debug_rt("jsex_rt: (%f + ) -> null", result->valuedouble);
            cJSON_Delete(result);
            result = cJSON_CreateNull();
        }

        cJSON_Delete(aux);
        break;

    case cJSON_String:
        aux = node->args[1]->function(node->args[1], value);

        if (cJSON_IsString(aux)) {
            offset = strlen(result->valuestring);
            string = malloc(offset + strlen(aux->valuestring) + 1);
            strcpy(string, result->valuestring);
            strcpy(string + offset, aux->valuestring);
            debug_rt("jsex_rt: (%s + %s) -> %s", result->valuestring, aux->valuestring, string);
            free(result->valuestring);
            result->valuestring = string;
        } else {
            debug_rt("jsex_rt: (%s + ) -> null", result->valuestring);
            cJSON_Delete(result);
            result = cJSON_CreateNull();
        }

        cJSON_Delete(aux);

        break;

    default:
        debug_rt("jsex_rt: ( + ) -> null");
        cJSON_Delete(result);
        result = cJSON_CreateNull();

    }

    return result;

    if (cJSON_IsNumber(result)) {
        aux = node->args[1]->function(node->args[1], value);

        if (cJSON_IsNumber(aux)) {
            number = result->valuedouble + aux->valuedouble;
            debug_rt("jsex_rt: (%f + %f) -> %f", result->valuedouble, aux->valuedouble, number);
            cJSON_SetNumberValue(result, number);
        } else {
            debug_rt("jsex_rt: (%f + ) -> null", result->valuedouble);
            cJSON_Delete(result);
            result = cJSON_CreateNull();
        }

        cJSON_Delete(aux);
    } else {
        debug_rt("jsex_rt: ( + ) -> null");
        cJSON_Delete(result);
        result = cJSON_CreateNull();
    }

    return result;
}

cJSON * jsex_rt_subtract(const jsex_t * node, const cJSON * value) {
    cJSON * result = node->args[0]->function(node->args[0], value);
    cJSON * aux;
    double number;

    if (cJSON_IsNumber(result)) {
        aux = node->args[1]->function(node->args[1], value);

        if (cJSON_IsNumber(aux)) {
            number = result->valuedouble - aux->valuedouble;
            debug_rt("jsex_rt: (%f - %f) -> %f", result->valuedouble, aux->valuedouble, number);
            cJSON_SetNumberValue(result, number);
        } else {
            debug_rt("jsex_rt: (%f - ) -> null", result->valuedouble);
            cJSON_Delete(result);
            result = cJSON_CreateNull();
        }

        cJSON_Delete(aux);
    } else {
        debug_rt("jsex_rt: ( - ) -> null");
        cJSON_Delete(result);
        result = cJSON_CreateNull();
    }

    return result;
}

cJSON * jsex_rt_multiply(const jsex_t * node, const cJSON * value) {
    cJSON * result = node->args[0]->function(node->args[0], value);
    cJSON * aux;
    double number;

    if (cJSON_IsNumber(result)) {
        aux = node->args[1]->function(node->args[1], value);

        if (cJSON_IsNumber(aux)) {
            number = result->valuedouble * aux->valuedouble;
            debug_rt("jsex_rt: (%f * %f) -> %f", result->valuedouble, aux->valuedouble, number);
            cJSON_SetNumberValue(result, number);
        } else {
            debug_rt("jsex_rt: (%f * ) -> null", result->valuedouble);
            cJSON_Delete(result);
            result = cJSON_CreateNull();
        }

        cJSON_Delete(aux);
    } else {
        debug_rt("jsex_rt: (*) -> null");
        cJSON_Delete(result);
        result = cJSON_CreateNull();
    }

    return result;
}

cJSON * jsex_rt_divide(const jsex_t * node, const cJSON * value) {
    cJSON * result = node->args[0]->function(node->args[0], value);
    cJSON * aux;
    double number;

    if (cJSON_IsNumber(result)) {
        aux = node->args[1]->function(node->args[1], value);

        if (cJSON_IsNumber(aux) && aux->valuedouble != 0) {
            number = result->valuedouble / aux->valuedouble;
            debug_rt("jsex_rt: (%f / %f) -> %f", result->valuedouble, aux->valuedouble, number);
            cJSON_SetNumberValue(result, number);
        } else {
            debug_rt("jsex_rt: (%f / ) -> null", result->valuedouble);
            cJSON_Delete(result);
            result = cJSON_CreateNull();
        }

        cJSON_Delete(aux);
    } else {
        debug_rt("jsex_rt: ( / ) -> null");
        cJSON_Delete(result);
        result = cJSON_CreateNull();
    }

    return result;
}

cJSON * jsex_rt_modulo(const jsex_t * node, const cJSON * value) {
    cJSON * result = node->args[0]->function(node->args[0], value);
    cJSON * aux;
    int number;

    if (cJSON_IsNumber(result)) {
        aux = node->args[1]->function(node->args[1], value);

        if (cJSON_IsNumber(aux) && aux->valueint != 0) {
            number = result->valueint % aux->valueint;
            debug_rt("jsex_rt: (%d %% %d) -> %d", result->valueint, aux->valueint, number);
            cJSON_SetNumberValue(result, number);
        } else {
            debug_rt("jsex_rt: (%d %% ) -> null", result->valueint);
            cJSON_Delete(result);
            result = cJSON_CreateNull();
        }

        cJSON_Delete(aux);
    } else {
        debug_rt("jsex_rt: (%%) -> null");
        cJSON_Delete(result);
        result = cJSON_CreateNull();
    }

    return result;
}

cJSON * jsex_rt_negate(const jsex_t * node, const cJSON * value) {
    cJSON * result = node->args[0]->function(node->args[0], value);

    switch (result->type) {
    case cJSON_False:
        result->type = cJSON_True;
        debug_rt("jsex_rt: (! false) -> true");
        break;

    case cJSON_True:
        result->type = cJSON_False;
        debug_rt("jsex_rt: (! true) -> false");
        break;

    default:
        debug_rt("jsex_rt: (! ) -> null");
        cJSON_Delete(result);
        result = cJSON_CreateNull();
    }

    return result;
}

cJSON * jsex_rt_opposite(const jsex_t * node, const cJSON * value) {
    cJSON * result = node->args[0]->function(node->args[0], value);

    if (cJSON_IsNumber(result)) {
        cJSON_SetNumberValue(result, -result->valuedouble);
        debug_rt("jsex_rt: (- %f) -> %f", -result->valuedouble, result->valuedouble);
    } else {
        debug_rt("jsex_rt: (- ) -> null");
        cJSON_Delete(result);
        result = cJSON_CreateNull();
    }

    return result;
}

cJSON * jsex_rt_int(const jsex_t * node, const cJSON * value) {
    cJSON * temp = node->args[0]->function(node->args[0], value);
    cJSON * result = jsex_cast_int(temp);
    debug_rt("jsex_rt: (int) -> %d", result->valueint);
    cJSON_Delete(temp);
    return result;
}

cJSON * jsex_rt_size(const jsex_t * node, const cJSON * value) {
    cJSON * temp = node->args[0]->function(node->args[0], value);
    cJSON * result;

    switch (temp->type) {
    case cJSON_String:
        result = cJSON_CreateNumber(strlen(temp->valuestring));
        debug_rt("jsex_rt: (size) -> %d", result->valueint);
        break;

    case cJSON_Array:
    case cJSON_Object:
        result = cJSON_CreateNumber(cJSON_GetArraySize(temp));
        debug_rt("jsex_rt: (size) -> %d", result->valueint);
        break;

    default:
        result = cJSON_CreateNull();
        debug_rt("jsex_rt: (size) -> null");
    }

    cJSON_Delete(temp);
    return result;
}

cJSON * jsex_rt_string(const jsex_t * node, const cJSON * value) {
    cJSON * temp = node->args[0]->function(node->args[0], value);
    cJSON * result = jsex_cast_string(temp);
    debug_rt("jsex_rt: (str) -> '%s'", result->valuestring);
    cJSON_Delete(temp);
    return result;
}

cJSON * jsex_rt_bool(const jsex_t * node, const cJSON * value) {
    cJSON * temp = node->args[0]->function(node->args[0], value);
    cJSON * result = jsex_cast_bool(temp);

    debug_rt("jsex_rt: (bool) -> '%s'", cJSON_IsTrue(result) ? "true" : "false");
    cJSON_Delete(temp);
    return result;
}

cJSON * jsex_rt_variable(const jsex_t * node, const cJSON * value) {
    cJSON * parent = NULL;
    cJSON * temp;
    cJSON * result;
    const cJSON * domain;

    // Optional child node (left part of the member)
    domain = node->args[0] ? (parent = node->args[0]->function(node->args[0], value)) : value;

    if (temp = cJSON_GetObjectItem(domain, node->value->valuestring), temp) {
        result = cJSON_Duplicate(temp, 1);
        debug_rt("jsex_rt: (.%s) -> (node)", node->value->valuestring);
    } else {
        result = cJSON_CreateNull();
        debug_rt("jsex_rt: (.%s) -> null", node->value->valuestring);
    }

    if (parent) {
        cJSON_Delete(parent);
    }

    return result;
}

cJSON * jsex_rt_index(const jsex_t * node, const cJSON * value) {
    cJSON * parent = NULL;
    cJSON * index;
    cJSON * temp;
    cJSON * result;
    const cJSON * domain;

    // Optional child node (left part of the member)

    domain = node->args[0] ? (parent = node->args[0]->function(node->args[0], value)) : value;
    index = node->args[1]->function(node->args[1], value);

    if (cJSON_IsNumber(index)) {

        if (temp = cJSON_GetArrayItem(domain, index->valueint), temp) {
            result = cJSON_Duplicate(temp, 1);
            debug_rt("jsex_rt: ([%d]) -> (node)", index->valueint);
        } else {
            result = cJSON_CreateNull();
            debug_rt("jsex_rt: ([%d]) -> null", index->valueint);
        }

    } else {
        result = cJSON_CreateNull();
        debug_rt("jsex_rt: ([]) -> null");
    }

    if (parent) {
        cJSON_Delete(parent);
    }

    cJSON_Delete(index);
    return result;
}

cJSON * jsex_rt_loop_all(const jsex_t * node, const cJSON * value) {
    cJSON * array;
    cJSON * result;
    cJSON child = { .string = node->value->valuestring };
    cJSON root = { .child = &child };
    cJSON * element;

    array = node->args[0]->function(node->args[0], value);

    // If size == 0, return False

    if (!array->child) {
        debug_rt("jsex_rt: (all '%s' in []) -> false", node->value->valuestring);
        cJSON_Delete(array);
        return cJSON_CreateFalse();
    }

    cJSON_ArrayForEach(element, array) {
        child.child = element->child;
        child.type = element->type;
        child.valuestring = element->valuestring;
        child.valueint = element->valueint;
        child.valuedouble = element->valuedouble;

        result = node->args[1]->function(node->args[1], &root);

        if (cJSON_IsFalse(result)) {
            debug_rt("jsex_rt: (all '%s' in [,]) -> false", node->value->valuestring);
            cJSON_Delete(result);
            cJSON_Delete(array);
            return cJSON_CreateFalse();
        } else {
            cJSON_Delete(result);
        }
    }

    debug_rt("jsex_rt: (all '%s' in [,]) -> true", node->value->valuestring);
    cJSON_Delete(array);
    return cJSON_CreateTrue();
}

cJSON * jsex_rt_loop_any(const jsex_t * node, const cJSON * value) {
    cJSON * array;
    cJSON * result;
    cJSON child = { .string = node->value->valuestring };
    cJSON root = { .child = &child };
    cJSON * element;

    array = node->args[0]->function(node->args[0], value);

    cJSON_ArrayForEach(element, array) {
        child.child = element->child;
        child.type = element->type;
        child.valuestring = element->valuestring;
        child.valueint = element->valueint;
        child.valuedouble = element->valuedouble;

        result = node->args[1]->function(node->args[1], &root);

        if (cJSON_IsTrue(result)) {
            debug_rt("jsex_rt: (any '%s' in [,]) -> true", node->value->valuestring);
            cJSON_Delete(result);
            cJSON_Delete(array);
            return cJSON_CreateTrue();
        } else {
            cJSON_Delete(result);
        }
    }

    debug_rt("jsex_rt: (any '%s' in [,]) -> false", node->value->valuestring);
    cJSON_Delete(array);
    return cJSON_CreateFalse();
}

cJSON * jsex_rt_root(__attribute__((unused)) const jsex_t * node, const cJSON * value) {
    return cJSON_Duplicate(value, 1);
}

cJSON * jsex_rt_value(const jsex_t * node, __attribute__((unused)) const cJSON * value) {
    return cJSON_Duplicate(node->value, 0);
}

/* Helper runtime functions ***************************************************/

cJSON * jsex_cast_bool(const cJSON * value) {
    cJSON * child;
    int number = 0;

    switch (value->type) {
    case cJSON_Invalid:
    case cJSON_False:
        break;

    case cJSON_True:
        number = 1;
        break;

    case cJSON_NULL:
        break;

    case cJSON_Number:
        number = value->valueint != 0;
        break;

    case cJSON_String:
        number = *value->valuestring != '\0';
        break;

    case cJSON_Array:
    case cJSON_Object:
        if (child = value->child, child && !child->next) {
            return jsex_cast_bool(child);
        }

        break;

    case cJSON_Raw:
        number = value->valuestring != '\0';
    default:
        debug("At jsex_cast_bool(): unknown value type (%d)", value->type);
    }

    return cJSON_CreateBool(number);
}

cJSON * jsex_cast_int(const cJSON * value) {
    int number = 0;
    char * end;
    cJSON * child;

    switch (value->type) {
    case cJSON_Invalid:
    case cJSON_False:
        break;

    case cJSON_True:
        number = 1;
        break;

    case cJSON_NULL:
        break;

    case cJSON_Number:
        number = value->valueint;
        break;

    case cJSON_String:
        number = (int)strtol(value->valuestring, &end, 10);
        number = end != value->valuestring ? number : 0;
        break;

    case cJSON_Array:
    case cJSON_Object:
        if (child = value->child, child && !child->next) {
            return jsex_cast_int(child);
        }
        break;

    case cJSON_Raw:
        break;

    default:
        debug("At jsex_cast_int(): unknown value type (%d)", value->type);
    }

    return cJSON_CreateNumber(number);
}

cJSON * jsex_cast_string(const cJSON * value) {
    cJSON * child;
    char *string = "";
    char buffer[64];

    switch (value->type) {
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
        if (value->valueint == value->valuedouble) {
            snprintf(buffer, 64, "%d", value->valueint);

        } else {
            snprintf(buffer, 64, "%f", value->valuedouble);

        }

        string = buffer;
        break;

    case cJSON_String:
        string = value->valuestring;
        break;

    case cJSON_Array:
    case cJSON_Object:
        if (child = value->child, child && !child->next) {
            return jsex_cast_string(child);
        }
        break;

    case cJSON_Raw:
        string = value->valuestring;
        break;

    default:
        debug("At jsex_cast_string(): unknown value type (%d)", value->type);
    }

    return cJSON_CreateString(string);
}
