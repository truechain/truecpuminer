#pragma once
/**
* rand.h
*   definitions for a random number generator
* -----------------------------------------------------------------------------
* By Bob Jenkins, 1996, Public Domain
* MODIFIED:
*   960327: Creation (addition of randinit, really)
*   970719: use context, not global variables, for internal state
*   980324: renamed seed to flag
*   980605: recommend RANDSIZL=4 for noncryptography.
*   010626: note this is public domain
* -----------------------------------------------------------------------------
*
* 2015-01-19: revised by cheungmine
*/
#ifndef _RAND_H__
#define _RAND_H__

#ifdef    __cplusplus
extern "C" {
#endif

#include "randstd.h"

#define RANDSIZL   (8)
#define RANDSIZ    (1<<RANDSIZL)

	/**
	* context of random number generator
	*/
	struct randctx_ub4
	{
		ub4 randcnt;
		ub4 seed[RANDSIZ];
		ub4 mm[RANDSIZ];
		ub4 aa;
		ub4 bb;
		ub4 cc;
	};
	typedef  struct randctx_ub4  randctx;


	/**
	* context of random number generator for 64-bits int
	*/
	struct randctx_ub8
	{
		ub8 randcnt;
		ub8 seed[RANDSIZ];
		ub8 mm[RANDSIZ];
		ub8 aa;
		ub8 bb;
		ub8 cc;
	};
	typedef  struct randctx_ub8  randctx64;


	/**
	* randinit
	*   init rand seed
	*/
	extern void rand_init(randctx *r, word time_as_seed);

	extern void rand64_init(randctx64 *r, word time_as_seed);

	/**
	* rand
	*   Call rand(randctx *) to retrieve a single 32-bit random value.
	*/
	extern ub4 rand32(randctx *r);

	extern ub4 randint(randctx *r, ub4 rmin, ub4 rmax);

	extern ub8 rand64(randctx64 *r);

	extern ub8 randint64(randctx64 *r, ub8 rmin, ub8 rmax);


#ifdef    __cplusplus
}
#endif

#endif  /* _RAND_H__ */
