/* JSex library
 * by Vikman
 * April 28, 2017
 */

#ifndef JSEX_H
#define JSEX_H

#include <regex.h>
#include <cJSON.h>

typedef struct jsex_t {
    cJSON * value;
    regex_t * regex;
    struct jsex_t * args[2];
    void (*function)(const struct jsex_t *, const cJSON *, cJSON *);
} jsex_t;

jsex_t * jsex_parse(const char * input);
cJSON * jsex_exec(const jsex_t * node, cJSON * value);
int jsex_test(const jsex_t * node, cJSON * value);
void jsex_free(jsex_t * node);
void jsex_cleanup();

#endif // JSEX_H
