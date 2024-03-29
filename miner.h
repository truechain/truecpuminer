#ifndef __MINER_H__
#define __MINER_H__

#include "cpuminer-config.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <curl/curl.h>
#include <jansson.h>

#ifdef WIN32
#define HAVE_STRUCT_TIMESPEC
#endif
#include <time.h>
#include <pthread.h>


#ifdef WIN32
#include <windows.h>
#include <winsock2.h>
#include <mstcpip.h>
#define inline _inline
#pragma warning(disable : 4996)
#else
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/resource.h>
#if HAVE_SYS_SYSCTL_H
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/sysctl.h>
#endif

#endif


#ifdef HAVE_ALLOCA_H
# include <alloca.h>
#elif !defined alloca
# ifdef __GNUC__
#  define alloca __builtin_alloca
# elif defined _AIX
#  define alloca __alloca
# elif defined _MSC_VER
#  include <malloc.h>
#  define alloca _alloca
# elif !defined HAVE_ALLOCA
#  ifdef  __cplusplus
extern "C"
#  endif
void *alloca (size_t);
# endif
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#else
enum {
	LOG_ERR,
	LOG_WARNING,
	LOG_NOTICE,
	LOG_INFO,
	LOG_DEBUG,
};
#endif

typedef intptr_t  ssize_t;

#ifdef WIN32
static inline void sleep(int secs)
{
	Sleep(secs * 1000);
}

enum {
	PRIO_PROCESS		= 0,
};

static inline int setpriority(int which, int who, int prio)
{
	return -!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
}
static inline int gettimeofday(struct timeval *tp, void *tzp)
{
	time_t clock;
	struct tm tm;
	SYSTEMTIME wtm;
	GetLocalTime(&wtm);
	tm.tm_year = wtm.wYear - 1900;
	tm.tm_mon = wtm.wMonth - 1;
	tm.tm_mday = wtm.wDay;
	tm.tm_hour = wtm.wHour;
	tm.tm_min = wtm.wMinute;
	tm.tm_sec = wtm.wSecond;
	tm.tm_isdst = -1;
	clock = mktime(&tm);
	tp->tv_sec = clock;
	tp->tv_usec = wtm.wMilliseconds * 1000;
	return (0);
}

#ifdef _MSC_VER
#define strcasecmp stricmp
#define strncasecmp  strnicmp 
#endif

#endif



#undef unlikely
#undef likely
#if defined(__GNUC__) && (__GNUC__ > 2) && defined(__OPTIMIZE__)
#define unlikely(expr) (__builtin_expect(!!(expr), 0))
#define likely(expr) (__builtin_expect(!!(expr), 1))
#else
#define unlikely(expr) (expr)
#define likely(expr) (expr)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#ifdef __linux /* Linux specific policy and affinity management */
#include <sched.h>
static inline void drop_policy(void)
{
	struct sched_param param;

#ifdef SCHED_IDLE
	if (unlikely(sched_setscheduler(0, SCHED_IDLE, &param) == -1))
#endif
#ifdef SCHED_BATCH
		sched_setscheduler(0, SCHED_BATCH, &param);
#endif
}

static inline void affine_to_cpu(int id, int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(&set), &set);
}
#elif defined(__FreeBSD__) /* FreeBSD specific policy and affinity management */
#include <sys/cpuset.h>
static inline void drop_policy(void)
{
}

static inline void affine_to_cpu(int id, int cpu)
{
	cpuset_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_CPUSET, -1, sizeof(cpuset_t), &set);
}
#else
static inline void drop_policy(void)
{
}

static inline void affine_to_cpu(int id, int cpu)
{
}
#endif




#define DATALENGTH  2048	 //2048 520
#define PMTSIZE  4
#define TBLSIZE  16
#define TARGETLEN	32
#define OFF_SKIP_LEN  32768 	     //32768  8230
#define OFF_CYCLE_LEN  8192	    	 //8192  2080
#define SKIP_CYCLE_LEN 2048     	//2048 520
#define HEADSIZE 32

#if ((__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3))
#define WANT_BUILTIN_BSWAP
#else
#define bswap_32(x) ((((x) << 24) & 0xff000000u) | (((x) << 8) & 0x00ff0000u) \
                   | (((x) >> 8) & 0x0000ff00u) | (((x) >> 24) & 0x000000ffu))
#endif

//#define make_new_seeds(seeds) unsigned char **seeds = malloc((OFF_CYCLE_LEN+SKIP_CYCLE_LEN) * sizeof(unsigned char *)); \
//							  if(seeds){ for(int i=0;i<OFF_CYCLE_LEN+SKIP_CYCLE_LEN;i++){ seeds[i] = 0; }}
//
//
//#define free_seeds(seeds) if(seeds){ for(int i=0;i<OFF_CYCLE_LEN+SKIP_CYCLE_LEN;i++){ \
//							if (seeds[i]) { free(seeds[i]); } } \
//							free(seeds); \
//						}

static inline uint32_t swab32(uint32_t v)
{
#ifdef WANT_BUILTIN_BSWAP
	return __builtin_bswap32(v);
#else
	return bswap_32(v);
#endif
}

#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif

#if !HAVE_DECL_BE32DEC
static inline uint32_t be32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) +
	    ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}
#endif

#if !HAVE_DECL_LE32DEC
static inline uint32_t le32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
	    ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}
#endif

#if !HAVE_DECL_BE32ENC
static inline void be32enc(void *pp, uint32_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[3] = x & 0xff;
	p[2] = (x >> 8) & 0xff;
	p[1] = (x >> 16) & 0xff;
	p[0] = (x >> 24) & 0xff;
}
#endif

#if !HAVE_DECL_LE32ENC
static inline void le32enc(void *pp, uint32_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[0] = x & 0xff;
	p[1] = (x >> 8) & 0xff;
	p[2] = (x >> 16) & 0xff;
	p[3] = (x >> 24) & 0xff;
}
#endif

#if JANSSON_MAJOR_VERSION >= 2
#define JSON_LOADS(str, err_ptr) json_loads((str), 0, (err_ptr))
#else
#define JSON_LOADS(str, err_ptr) json_loads((str), (err_ptr))
#endif

#define PROTOCOL_NAME 		"TrueStratum" 
#define PROTOCOL_VERSION 	"0.1.0" 
#define USER_AGENT 		PACKAGE_NAME "/" PACKAGE_VERSION
#define STRATUM_AGETN   PROTOCOL_NAME "/" PROTOCOL_VERSION


#if defined(__ARM_NEON__) || defined(__i386__) || defined(__x86_64__)
#define HAVE_SHA256_4WAY 1
int sha256_use_4way();
void sha256_init_4way(uint32_t *state);
void sha256_transform_4way(uint32_t *state, const uint32_t *block, int swap);
#endif

#if defined(__x86_64__) && defined(USE_AVX2)
#define HAVE_SHA256_8WAY 1
int sha256_use_8way();
void sha256_init_8way(uint32_t *state);
void sha256_transform_8way(uint32_t *state, const uint32_t *block, int swap);
#endif



struct thr_info {
	int		id;
	pthread_t	pth;
	struct thread_q	*q;
};

struct work_restart {
	volatile unsigned long	restart;
	volatile unsigned long  stopped;
	char			padding[128 - sizeof(unsigned long)];
};

struct work {
	uint8_t target[TARGETLEN];
	uint8_t hash[32];
	uint8_t mixHash[32];
	uint64_t nonce;

	bool done;
	bool submit;
};

extern bool opt_debug;
extern bool opt_protocol;
extern int opt_timeout;
extern bool have_longpoll;
extern bool want_stratum;
extern bool have_stratum;
extern char *opt_cert;
extern char *opt_proxy;
extern long opt_proxy_type;
extern bool use_syslog;
extern pthread_mutex_t applog_lock;
extern struct thr_info *thr_info;
extern int longpoll_thr_id;
extern int stratum_thr_id;
extern struct work_restart *work_restart;


extern void applog(int prio, const char *fmt, ...);
extern char *bin2hex(const unsigned char *p, size_t len);
extern bool hex2bin(unsigned char *p, const char *hexstr, size_t len);
extern int timeval_subtract(struct timeval *result, struct timeval *x,
	struct timeval *y);

struct stratum_job {
	unsigned char seedhash[32];
	unsigned char headhash[32];
	unsigned char target[TARGETLEN];
	unsigned char version[4];
	bool new_work;
	bool clean;
	double diff;
};

struct stratum_ctx {
	char *url;

	CURL *curl;
	char *curl_url;
	char curl_err_str[CURL_ERROR_SIZE];
	curl_socket_t sock;
	size_t sockbuf_size;
	char *sockbuf;
	pthread_mutex_t sock_lock;

	struct stratum_job job;
	pthread_mutex_t work_lock;
};

struct true_dataset{
	uint64_t *dataset;
	uint8_t  seedhash[32];
	int 	len;
	volatile uint32_t update;
};

bool stratum_socket_full(struct stratum_ctx *sctx, int timeout);
bool stratum_send_line(struct stratum_ctx *sctx, char *s);
char *stratum_recv_line(struct stratum_ctx *sctx);
bool stratum_connect(struct stratum_ctx *sctx, const char *url);
void stratum_disconnect(struct stratum_ctx *sctx);
void stratum_request_work(struct stratum_ctx *sctx);
bool stratum_authorize(struct stratum_ctx *sctx, const char *coinbase, const char *user, const char* mail);
bool stratum_handle_method(struct stratum_ctx *sctx, const char *s);
bool stratum_update_dataset(struct stratum_ctx *sctx, const char *curseedhash, uint8_t seeds[OFF_CYCLE_LEN + SKIP_CYCLE_LEN][16],unsigned char seedhash[32]);
uint64_t* updateLookupTBL(uint8_t seeds[OFF_CYCLE_LEN+SKIP_CYCLE_LEN][16],uint64_t *plookupTbl,int plen);
void truehashTableInit(uint64_t *tableLookup,int tlen);

bool dataset_hash(uint8_t hash[32], uint64_t *data,int len);
inline int scanhash_sha512(int thr_id, const uint64_t *dataset, int dlen, uint8_t hash[HEADSIZE], uint8_t target[TARGETLEN],
	uint8_t mixhash[HEADSIZE], uint64_t *nonce, uint64_t max_nonce, uint64_t *hashes_done);
void check_seed_head_hash(uint8_t seedhash[OFF_CYCLE_LEN + SKIP_CYCLE_LEN][16]);

void get_hashrate(char rate[256]);
void get_work_id(char headhash[64]);
void test_minerva();

struct thread_q;

extern struct thread_q *tq_new(void);
extern void tq_free(struct thread_q *tq);
extern bool tq_push(struct thread_q *tq, void *data);
extern void *tq_pop(struct thread_q *tq, const struct timespec *abstime);
extern void tq_freeze(struct thread_q *tq);
extern void tq_thaw(struct thread_q *tq);

#endif /* __MINER_H__ */
