/**
* rand.c
*   By Bob Jenkins.  My random number generator, ISAAC.  Public Domain.
* -----------------------------------------------------------------------------
* MODIFIED:
*   960327: Creation (addition of randinit, really)
*   970719: use context, not global variables, for internal state
*   980324: added main (ifdef'ed out), also rearranged randinit()
*   010626: Note that this is public domain
* -----------------------------------------------------------------------------
*
* 2015-01-19: revised by cheungmine
*/
#include "rand.h"

#include <time.h>

/**
*==============================================================================
* 32-bits int random generator
*==============================================================================
*/
#define isaac_golden_ratio32  0x9e3779b9
#define ind32(mm,x)  (*(ub4 *)((ub1 *)(mm) + ((x) & ((RANDSIZ-1)<<2))))
#define rngstep32(mix,a,b,mm,m,m2,r,x) \
{ \
    x = *m;  \
    a = (a^(mix)) + *(m2++); \
    *(m++) = y = ind32(mm,x) + a + b; \
    *(r++) = b = ind32(mm,y>>RANDSIZL) + x; \
}

#define mix32(a,b,c,d,e,f,g,h) \
{ \
    a^=b<<11; d+=a; b+=c; \
    b^=c>>2;  e+=b; c+=d; \
    c^=d<<8;  f+=c; d+=e; \
    d^=e>>16; g+=d; e+=f; \
    e^=f<<10; h+=e; f+=g; \
    f^=g>>4;  a+=f; g+=h; \
    g^=h<<8;  b+=g; h+=a; \
    h^=a>>9;  c+=h; a+=b; \
}

static void isaac32(randctx *ctx)
{
	register ub4 a, b, x, y, *m, *mm, *m2, *r, *mend;
	mm = ctx->mm;
	r = ctx->seed;
	a = ctx->aa;
	b = ctx->bb + (++ctx->cc);

	for (m = mm, mend = m2 = m + (RANDSIZ / 2); m < mend; ) {
		rngstep32(a << 13, a, b, mm, m, m2, r, x);
		rngstep32(a >> 6, a, b, mm, m, m2, r, x);
		rngstep32(a << 2, a, b, mm, m, m2, r, x);
		rngstep32(a >> 16, a, b, mm, m, m2, r, x);
	}

	for (m2 = mm; m2 < mend; ) {
		rngstep32(a << 13, a, b, mm, m, m2, r, x);
		rngstep32(a >> 6, a, b, mm, m, m2, r, x);
		rngstep32(a << 2, a, b, mm, m, m2, r, x);
		rngstep32(a >> 16, a, b, mm, m, m2, r, x);
	}

	ctx->bb = b;
	ctx->aa = a;
}

#define gen_rand32(r) \
    (!(r)->randcnt-- ? \
        (isaac32(r), (r)->randcnt=RANDSIZ-1, (r)->seed[(r)->randcnt]) : \
        (r)->seed[(r)->randcnt])


void rand_init(randctx *ctx, word time_as_seed)
{
	word i;
	ub4 a, b, c, d, e, f, g, h;
	ub4 *m, *r;
	ctx->aa = ctx->bb = ctx->cc = 0;
	m = ctx->mm;
	r = ctx->seed;
	a = b = c = d = e = f = g = h = isaac_golden_ratio32; /* the golden ratio */

														  /* init seed */
	for (i = 0; i < 256; ++i) {
		r[i] = (ub4)(time_as_seed ? time(0) : 0);
	}

	for (i = 0; i < 4; ++i) {                                 /* scramble it */
		mix32(a, b, c, d, e, f, g, h);
	}

	if (1) {
		/* initialize using the contents of r[] as the seed */
		for (i = 0; i < RANDSIZ; i += 8) {
			a += r[i]; b += r[i + 1]; c += r[i + 2]; d += r[i + 3];
			e += r[i + 4]; f += r[i + 5]; g += r[i + 6]; h += r[i + 7];
			mix32(a, b, c, d, e, f, g, h);
			m[i] = a; m[i + 1] = b; m[i + 2] = c; m[i + 3] = d;
			m[i + 4] = e; m[i + 5] = f; m[i + 6] = g; m[i + 7] = h;
		}

		/* do a second pass to make all of the seed affect all of m */
		for (i = 0; i < RANDSIZ; i += 8) {
			a += m[i]; b += m[i + 1]; c += m[i + 2]; d += m[i + 3];
			e += m[i + 4]; f += m[i + 5]; g += m[i + 6]; h += m[i + 7];
			mix32(a, b, c, d, e, f, g, h);
			m[i] = a; m[i + 1] = b; m[i + 2] = c; m[i + 3] = d;
			m[i + 4] = e; m[i + 5] = f; m[i + 6] = g; m[i + 7] = h;
		}
	}
	else {
		/* Never run to this: fill in m[] with messy stuff */
		for (i = 0; i < RANDSIZ; i += 8) {
			mix32(a, b, c, d, e, f, g, h);
			m[i] = a; m[i + 1] = b; m[i + 2] = c; m[i + 3] = d;
			m[i + 4] = e; m[i + 5] = f; m[i + 6] = g; m[i + 7] = h;
		}
	}

	isaac32(ctx);              /* fill in the first set of results */
	ctx->randcnt = RANDSIZ;  /* prepare to use the first set of results */
}


/**
* randint
*   get 32-bits unsigned integer random
*/
ub4 rand32(randctx *r)
{
	return gen_rand32(r);
}


/**
* randint
*   get integer random between rmin and rmax
*/
ub4 randint(randctx *r, ub4 rmin, ub4 rmax)
{
	if (!r->randcnt--) {
		isaac32(r);
		r->randcnt = RANDSIZ - 1;
	}

	ub4 ret = (ub4)r->seed[r->randcnt];

	return ret % (ub4)(rmax - rmin + 1) + rmin;
}


/**
*==============================================================================
* 64 bits int random generator
*==============================================================================
*/
#define isaac_golden_ratio64  0x9e3779b97f4a7c13LL
#define ind64(mm,x)  (*(ub8 *)((ub1 *)(mm) + ((x) & ((RANDSIZ-1)<<3))))
#define rngstep64(mix,a,b,mm,m,m2,r,x) \
{ \
    x = *m;  \
    a = (mix) + *(m2++); \
    *(m++) = y = ind64(mm,x) + a + b; \
    *(r++) = b = ind64(mm,y>>RANDSIZL) + x; \
}

#define mix64(a,b,c,d,e,f,g,h) \
{ \
    a-=e; f^=h>>9;  h+=a; \
    b-=f; g^=a<<9;  a+=b; \
    c-=g; h^=b>>23; b+=c; \
    d-=h; a^=c<<15; c+=d; \
    e-=a; b^=d>>14; d+=e; \
    f-=b; c^=e<<20; e+=f; \
    g-=c; d^=f>>17; f+=g; \
    h-=d; e^=g<<14; g+=h; \
}

static void isaac64(randctx64 *ctx)
{
	register ub8 a, b, x, y, *m, *mm, *m2, *r, *mend;
	mm = ctx->mm;
	r = ctx->seed;
	a = ctx->aa;
	b = ctx->bb + (++ctx->cc);

	for (m = mm, mend = m2 = m + (RANDSIZ / 2); m < mend; ) {
		rngstep64(~(a ^ (a << 21)), a, b, mm, m, m2, r, x);
		rngstep64(a ^ (a >> 5), a, b, mm, m, m2, r, x);
		rngstep64(a ^ (a << 12), a, b, mm, m, m2, r, x);
		rngstep64(a ^ (a >> 33), a, b, mm, m, m2, r, x);
	}

	for (m2 = mm; m2 < mend; ) {
		rngstep64(~(a ^ (a << 21)), a, b, mm, m, m2, r, x);
		rngstep64(a ^ (a >> 5), a, b, mm, m, m2, r, x);
		rngstep64(a ^ (a << 12), a, b, mm, m, m2, r, x);
		rngstep64(a ^ (a >> 33), a, b, mm, m, m2, r, x);
	}
	ctx->bb = b;
	ctx->aa = a;
}


#define gen_rand64(r) \
    (!(r)->randcnt-- ? (isaac64(r), (r)->randcnt=RANDSIZ-1, (r)->seed[(r)->randcnt]) : \
        (r)->seed[(r)->randcnt])


void rand64_init(randctx64 *ctx, word time_as_seed)
{
	word i;
	ub8 a, b, c, d, e, f, g, h;
	ub8 *mm, *r;
	ctx->aa = ctx->bb = ctx->cc = (ub8)0;

	a = b = c = d = e = f = g = h = isaac_golden_ratio64;  /* the golden ratio */

	mm = ctx->mm;
	r = ctx->seed;

	/* init seed */
	for (i = 0; i < 256; ++i) {
		r[i] = (ub8)(time_as_seed ? time(0) : 0);
	}

	for (i = 0; i < 4; ++i) {                   /* scramble it */
		mix64(a, b, c, d, e, f, g, h);
	}

	for (i = 0; i < RANDSIZ; i += 8) {  /* fill in mm[] with messy stuff */
		if (1) {               /* use all the information in the seed */
			a += r[i]; b += r[i + 1]; c += r[i + 2]; d += r[i + 3];
			e += r[i + 4]; f += r[i + 5]; g += r[i + 6]; h += r[i + 7];
		}
		mix64(a, b, c, d, e, f, g, h);
		mm[i] = a; mm[i + 1] = b; mm[i + 2] = c; mm[i + 3] = d;
		mm[i + 4] = e; mm[i + 5] = f; mm[i + 6] = g; mm[i + 7] = h;
	}

	if (1) {
		/* do a second pass to make all of the seed affect all of mm */
		for (i = 0; i < RANDSIZ; i += 8) {
			a += mm[i]; b += mm[i + 1]; c += mm[i + 2]; d += mm[i + 3];
			e += mm[i + 4]; f += mm[i + 5]; g += mm[i + 6]; h += mm[i + 7];
			mix64(a, b, c, d, e, f, g, h);
			mm[i] = a; mm[i + 1] = b; mm[i + 2] = c; mm[i + 3] = d;
			mm[i + 4] = e; mm[i + 5] = f; mm[i + 6] = g; mm[i + 7] = h;
		}
	}

	isaac64(ctx);             /* fill in the first set of results */
	ctx->randcnt = RANDSIZ;   /* prepare to use the first set of results */
}


/**
* rand64
*   get 64-bits unsigned integer random
*/
ub8 rand64(randctx64 *r)
{
	return (ub8)(gen_rand64(r));
}


/**
* randint64
*   get 64-bits unsigned integer random
*/
ub8 randint64(randctx64 *r, ub8 rmin, ub8 rmax)
{
	if (!r->randcnt--) {
		isaac64(r);
		r->randcnt = RANDSIZ - 1;
	}

	ub8 ret = (ub8)r->seed[r->randcnt];

	return ret % (ub8)(rmax - rmin + 1) + rmin;
}


#ifdef NEVER
static void inner_test32()
{
	ub4 i, j;
	randctx ctx;
	rand_init(&ctx, RAND_FALSE);

	for (i = 0; i < 2; ++i) {
		isaac32(&ctx);

		for (j = 0; j < 256; ++j) {
			printf("%.8lx", ctx.seed[j]);
			if ((j & 7) == 7) {
				printf("\n");
			}
		}
	}
}


static void inner_test64()
{
	ub8 i, j;
	randctx64 ctx;
	rand64_init(&ctx, RAND_FALSE);

	for (i = 0; i < 2; ++i) {
		isaac64(&ctx);

		for (j = 0; j < RANDSIZ; ++j) {
			printf("%.8lx%.8lx", (ub4)(ctx.seed[j] >> 32), (ub4)ctx.seed[j]);

			if ((j & 3) == 3) {
				printf("\n");
			}
		}
	}
}


static void usage()
{
	int i;

	randctx ctx;
	randctx64 ctx64;

	rand_init(&ctx, RAND_TRUE);

	rand64_init(&ctx64, RAND_TRUE);


	for (i = 0; i < 100; ++i) {
		printf("%03d: %d\n", i, (sb4)randint(&ctx, -100, 100));
		printf("%03d: %lld\n", i, (sb8)randint64(&ctx64, -100, 100));
	}
}


int main()
{
	inner_test32();
	inner_test64();

	usage();
}

#endif
