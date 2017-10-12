C=gcc
CFLAGS=-I. -O3 -funroll-loops -ggdb -std=c99
DEPS = bp.h
OBJ = bp_fp12.c  bp_fp2.c  bp_fp6.c  bp_g1.c  bp_g2.c  bp_g2_mult.c  bp_group.c  bp_gt.c  bp_map.c
LIB = bp

%.o: %.c $(DEPS)
	$(CC)  -fpic -c -o $@ $< $(CFLAGS)

bp: $(OBJ)
	gcc -shared -fpic -o lib$(LIB).so $(OBJ)

clean:
	rm *.o *.so

