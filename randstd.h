#pragma once
/**
* randstd.h
*
*   Standard definitions and types, Bob Jenkins
*
* 2015-01-19: revised by cheungmine
*/
#ifndef _RANDSTD_H__
#define _RANDSTD_H__

#ifndef STDIO
#  include <stdio.h>
#  define STDIO
#endif

#ifndef STDDEF
#  include <stddef.h>
#  define STDDEF
#endif

typedef unsigned long long ub8;
#define UB8MAXVAL 0xffffffffffffffffLL
#define UB8BITS 64

typedef signed long long sb8;
#define SB8MAXVAL 0x7fffffffffffffffLL

typedef unsigned long int ub4;   /* unsigned 4-byte quantities */
#define UB4MAXVAL 0xffffffff

typedef signed long int sb4;
#define UB4BITS 32
#define SB4MAXVAL 0x7fffffff

typedef unsigned short int ub2;
#define UB2MAXVAL 0xffff
#define UB2BITS 16

typedef signed short int sb2;
#define SB2MAXVAL 0x7fff

/* unsigned 1-byte quantities */
typedef unsigned char ub1;
#define UB1MAXVAL 0xff
#define UB1BITS 8

/* signed 1-byte quantities */
typedef signed char sb1;
#define SB1MAXVAL 0x7f

/* fastest type available */
typedef int word;

#define bis(target,mask)  ((target) |=  (mask))
#define bic(target,mask)  ((target) &= ~(mask))
#define bit(target,mask)  ((target) &   (mask))

#ifndef min
#  define min(a,b) (((a)<(b)) ? (a) : (b))
#endif /* min */

#ifndef max
#  define max(a,b) (((a)<(b)) ? (b) : (a))
#endif /* max */

#ifndef abs
#  define abs(a)   (((a)>0) ? (a) : -(a))
#endif

#ifndef align
#  define align(a) (((ub4)a+(sizeof(void *)-1))&(~(sizeof(void *)-1)))
#endif /* align */

#define RAND_TRUE    1
#define RAND_FALSE   0

#define RAND_SUCCESS 0  /* 1 on VAX */

#endif /* _RANDSTD_H__ */
