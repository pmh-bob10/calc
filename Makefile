calc: calc.l calc.y calc.h
	bison -d calc.y
	flex -ocalc.lex.c calc.l
	cc -o $@ calc.tab.c calc.lex.c calc.funcs.c -lm
