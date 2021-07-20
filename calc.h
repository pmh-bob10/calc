/* interface to the lexer */
extern int yylineno; /* from lexer */
void yyerror(char *s, ...);

enum bifs {
  B_sqrt = 1,
  B_exp,
  B_log,
  B_print
};

/* nodes in the abstract syntax tree */
struct ast {
  int nodetype;
  struct ast *l;
  struct ast *r;
};

struct fncall {
  int nodetype;
  struct ast *l;
  enum bifs functype;
};

struct ufncall {
  int nodetype;
  struct ast *l;
  struct symbol *s;
};

struct flow {
  int nodetype;
  struct ast *cond;
  struct ast *tl;
  struct ast *el;
};

struct numval {
  int nodetype;
  double number;
};

struct symref {
  int nodetype;
  struct symbol *s;
};

struct symasgn {
  int nodetype;
  struct symbol *s;
  struct ast *v;
};

/* build an AST */
struct ast *newast(int nodetype, struct ast *l, struct ast *r);
struct ast *newcmp(int cmptype, struct ast *l, struct ast *r);
struct ast *newfunc(int functype, struct ast *l);
struct ast *newcall(struct symbol *s, struct ast *l);
struct ast *newref(struct symbol *s);
struct ast *newasgn(struct symbol *s, struct ast *v);
struct ast *newnum(double d);
struct ast *newflow(int nodetype, struct ast *cond, struct ast *tl, struct ast *tr);

/* evaluate an AST */
double eval(struct ast *);

/* delete and free an AST */
void treefree(struct ast *);

/* symbol table */
struct symbol {
  char *name; /* a variable name */
  double value;
  struct ast *func; /* stmt for the function */
  struct symlist *syms; /* list of dummy args */
};

/* simple symtab of fixed size */
#define NHASH 9997

struct symbol *lookup(char*);

/* list of symbols, for an argument list */
struct symlist {
  struct symbol *sym;
  struct symlist *next;
};

struct symlist *newsymlist(struct symbol *sym, struct symlist *next);
void symlistfree(struct symlist *sl);

/* define a function */
void dodef(struct symbol *name, struct symlist *syms, struct ast *stmts);
