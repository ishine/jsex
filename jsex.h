/* JSex library
 * by Vikman
 * April 28, 2017
 */

typedef struct jsex_token_t {
    int type;
    char *string;
} jsex_token_t;

jsex_token_t* jsex_lexer(const char *input);
void jsex_token_free(jsex_token_t *tokens);
void jsex_cleanup();
