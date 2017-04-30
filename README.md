# JSex
**JSON Expression Match Library**

This project aims to create a language for building assertions on JSON objects.

It has two main components:

- Lexer and parser to compile an expression into a `JSex` structure.
- Engine to execute `JSex` structures over a JSON object.

This project will use POSIX Regular Expressions Library and [cJSON Library](https://github.com/DaveGamble/cJSON) by Dave Gamble.

## Language

- **Keywords**: `all`, `any`, `in`, `null`
- **Functions**: `size()`, `int()`, `str()`, `float()`
- **Comparators**: `==`, `!=`, `<`, `>`, `<=`, `>=`, `=~`
- **Operators**: `[`, `]`, `+`, `-`, `*`, `/`, `%`, `&&`, `||`, `!`
- **Tokens**: `.`, `:`, `(`, `)`, `"`, `'`

## Expression examples

- `size(person.children) > 2 && any x in person.children: (x.name =~ "^S.*" || int(x.age) == person.age - 4)`
- `size(a.b) > 2 && any x in a.b: (x =~ "sg*" || int(x) == 4)`
- `a.b[a.d + 2] == 4 && all x in a.c: (x.value > 7 || x.comment == null || x.children[0] == 2)`
