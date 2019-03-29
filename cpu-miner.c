/*
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"
#define _GNU_SOURCE

#include "miner.h"

#define PROGRAM_NAME	"true-minerd"
// #define DEF_RPC_URL		"http://127.0.0.1:9332/"
#define DEF_RPC_URL	 "stratum+tcp://192.168.1.101:8788"
#define LP_SCANTIME		60


		
enum workio_commands {
	WC_GET_WORK,
	WC_SUBMIT_WORK,
};

struct workio_cmd {
	enum workio_commands	cmd;
	struct thr_info		*thr;
	union {
		struct work	*work;
	} u;
};

bool opt_debug = false;
bool opt_protocol = false;
static bool opt_benchmark = false;
bool have_longpoll = false;
bool want_stratum = true;
bool have_stratum = true;
bool use_syslog = false;
static bool opt_background = false;
static bool opt_quiet = false;
static int opt_retries = -1;
static int opt_fail_pause = 30;
int opt_timeout = 270;
static json_t *opt_config;
static const bool opt_time = true;
static int opt_n_threads;
static int num_processors;
static char *rpc_url;
static char *rpc_user,*coin_base,*mail;
char *opt_cert;
char *opt_proxy;
long opt_proxy_type;
struct thr_info *thr_info;
static int work_thr_id;
int longpoll_thr_id = -1;
int stratum_thr_id = -1;
struct work_restart *work_restart = NULL;
static struct stratum_ctx stratum;
static struct work g_work;
static time_t g_work_time;
static pthread_mutex_t g_work_lock;

pthread_mutex_t applog_lock;
pthread_mutex_t stats_lock;

static unsigned long accepted_count = 0L;
static unsigned long rejected_count = 0L;
double *thr_hashrates;
static struct true_dataset _ds;
static bool running = true;

#ifdef HAVE_GETOPT_LONG
#ifdef WIN32
#include "getopt.h"
#else
#include <getopt.h>
#endif
#else
struct option {
	const char *name;
	int has_arg;
	int *flag;
	int val;
};
#endif

static char const usage[] = "\
Usage: " PROGRAM_NAME " [OPTIONS]\n\
Options:\n\
  -o, --url=URL         URL of mining server (default: " DEF_RPC_URL ")\n\
  -C, --coinbase=0x***  coinbase for mining reward(34 char length)\n\
  -u, --user=USERNAME   username for mining server\n\
  -m, --mail=Mail       mail for mining server\n\
      --cert=FILE       certificate for mining server using SSL\n\
  -x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy\n\
  -t, --threads=N       number of miner threads (default: number of processors)\n\
  -r, --retries=N       number of times to retry if a network call fails\n\
                          (default: retry indefinitely)\n\
  -R, --retry-pause=N   time to pause between retries, in seconds (default: 30)\n\
  -T, --timeout=N       network timeout, in seconds (default: 270)\n\
  -q, --quiet           disable per-thread hashmeter output\n\
  -D, --debug           enable debug output\n\
  -P, --protocol-dump   verbose dump of protocol-level activities\n"
#ifdef HAVE_SYSLOG_H
"\
  -S, --syslog          use system log for output messages\n"
#endif
#ifndef WIN32
"\
  -B, --background      run the miner in the background\n"
#endif
"\
      --benchmark       run in offline benchmark mode\n\
  -c, --config=FILE     load a JSON-format configuration file\n\
  -V, --version         display version information and exit\n\
  -h, --help            display this help text and exit\n\
";

static char const short_options[] =
#ifndef WIN32
	"B"
#endif
#ifdef HAVE_SYSLOG_H
	"S"
#endif
	"c:Dhm:Px:qr:R:s:t:T:o:u:C:V";

static struct option const options[] = {
#ifndef WIN32
	{ "background", 0, NULL, 'B' },
#endif
	{ "benchmark", 0, NULL, 1005 },
	{ "cert", 1, NULL, 1001 },
	{ "config", 1, NULL, 'c' },
	{ "debug", 0, NULL, 'D' },
	{ "help", 0, NULL, 'h' },
	{ "mail", 1, NULL, 'm' },
	{ "protocol-dump", 0, NULL, 'P' },
	{ "proxy", 1, NULL, 'x' },
	{ "quiet", 0, NULL, 'q' },
	{ "retries", 1, NULL, 'r' },
	{ "retry-pause", 1, NULL, 'R' },
#ifdef HAVE_SYSLOG_H
	{ "syslog", 0, NULL, 'S' },
#endif
	{ "threads", 1, NULL, 't' },
	{ "timeout", 1, NULL, 'T' },
	{ "url", 1, NULL, 'o' },
	{ "user", 1, NULL, 'u' },
	{ "coinbase", 1, NULL, 'C' },
	{ "version", 0, NULL, 'V' },
	{ 0, 0, 0, 0 }
};


static void init_dataset() {
    if (_ds.dataset == 0) {
        _ds.len = TBLSIZE*DATALENGTH*PMTSIZE*32;
        _ds.dataset = calloc(_ds.len,sizeof(uint64_t));
        truehashTableInit(_ds.dataset,_ds.len);
        dataset_hash(_ds.seedhash,_ds.dataset,_ds.len);
    }
}
static void free_dataset() {
    if (_ds.dataset != 0) {
        free(_ds.dataset);
        _ds.dataset = 0;
    } 
}
static inline bool match_ds_hash(uint8_t hash[32]) {
    return 0 == memcmp(_ds.seedhash,hash,32);
}
static bool wait_stop_use_dataset() {
    int pos = 0;
    while(1){
        pos= 0;
        for(int i=0;i<opt_n_threads;i++) {
            if (work_restart[i].stopped == 1) {
                pos++;
            }            
        }
        if (pos >= opt_n_threads) break;
        sleep(1);
    }    
    return true;
}
static void update_use_dataset() {
    for (int i = 0; i < opt_n_threads; i++)
		work_restart[i].stopped = 0;
}
inline void restart_threads(void)
{
	for (int i = 0; i < opt_n_threads; i++)
		work_restart[i].restart = 1;
}
void get_work_id(char headhash[64]) {
	if (g_work.done) {
		char *p = bin2hex(g_work.hash, 32);
		memcpy(headhash, p, 64);
	}
}
inline bool empty_hash(unsigned char hash[32]) {
	unsigned char empty[32] = { 0 };
	return 0 == memcmp(empty, hash, 32);
}
static bool jobj_binary(const json_t *obj, const char *key,void *buf, size_t buflen)
{
	const char *hexstr;
	json_t *tmp;

	tmp = json_object_get(obj, key);
	if (unlikely(!tmp)) {
		applog(LOG_ERR, "JSON key '%s' not found", key);
		return false;
	}
	hexstr = json_string_value(tmp);
	if (unlikely(!hexstr)) {
		applog(LOG_ERR, "JSON key '%s' is not a string", key);
		return false;
	}
	if (!hex2bin(buf, hexstr, buflen))
		return false;

	return true;
}

static void share_result(int result, const char *reason)
{
	char s[345];
	double hashrate;
	int i;

	hashrate = 0.;
	pthread_mutex_lock(&stats_lock);
	for (i = 0; i < opt_n_threads; i++)
		hashrate += thr_hashrates[i];
	result ? accepted_count++ : rejected_count++;
	pthread_mutex_unlock(&stats_lock);
	
	sprintf(s, hashrate >= 1e6 ? "%.0f" : "%.2f", 1e-3 * hashrate);
	applog(LOG_INFO, "accepted: %lu/%lu (%.2f%%), %s khash/s %s",
		   accepted_count,
		   accepted_count + rejected_count,
		   100. * accepted_count / (accepted_count + rejected_count),
		   s,
		   result ? "(yay!!!)" : "(booooo)");

	if (opt_debug && reason)
		applog(LOG_DEBUG, "DEBUG: reject reason: %s", reason);
}

static bool submit_upstream_work(CURL *curl, struct work *work)
{
	char s[256]={0};
	char *head = bin2hex((const unsigned char *)(&work->hash), 32);
	char *mix = bin2hex((const unsigned char *)(&work->mixHash), 32);
	sprintf(s,"{\"id\":3,\"jsonrpc\": \"2.0\",\"method\": \"etrue_submitWork\", \"params\": [\"%llu\", \"%s\", \"%s\"]}",
		work->nonce, head, mix);
	free(head);
	free(mix);

	if (unlikely(!stratum_send_line(&stratum, s)))
	{
		applog(LOG_ERR, "submit_upstream_work stratum_send_line failed");
		return false;
	}
	return true;
}

static void workio_cmd_free(struct workio_cmd *wc)
{
	if (!wc)
		return;

	switch (wc->cmd) {
	case WC_SUBMIT_WORK:
		free(wc->u.work);
		break;
	default: /* do nothing */
		break;
	}

	memset(wc, 0, sizeof(*wc));	/* poison */
	free(wc);
}

static bool workio_submit_work(struct workio_cmd *wc, CURL *curl)
{
	int failures = 0;

	/* submit solution to true-pool via JSON-RPC */
	while (!submit_upstream_work(curl, wc->u.work)) {
		if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
			applog(LOG_ERR, "...terminating workio thread");
			return false;
		}

		/* pause, then restart work-request loop */
		applog(LOG_ERR, "...retry after %d seconds",
			opt_fail_pause);
		sleep(opt_fail_pause);
	}
	stratum_request_work(&stratum);
	return true;
}

static void *workio_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	CURL *curl;
	bool ok = true;
	applog(LOG_INFO, "workio_thread start");

	curl = curl_easy_init();
	if (unlikely(!curl)) {
		applog(LOG_ERR, "CURL initialization failed");
		return NULL;
	}
	
	while (running & ok) {
		struct workio_cmd *wc;

		/* wait for workio_cmd sent to us, on our queue */
		wc = tq_pop(mythr->q, NULL);
		if (!wc) {
			ok = false;
			break;
		}

		/* process workio_cmd */
		switch (wc->cmd) {
		case WC_SUBMIT_WORK:
			ok = workio_submit_work(wc, curl);
			break;

		default:		/* should never happen */
			ok = false;
			break;
		}

		workio_cmd_free(wc);
	}

	tq_freeze(mythr->q);
	curl_easy_cleanup(curl);

	return NULL;
}

static bool submit_work(struct thr_info *thr, const struct work *work_in)
{
	struct workio_cmd *wc;
	
	/* fill out work request message */
	wc = calloc(1, sizeof(*wc));
	if (!wc)
		return false;

	wc->u.work = malloc(sizeof(*work_in));
	if (!wc->u.work)
		goto err_out;

	wc->cmd = WC_SUBMIT_WORK;
	wc->thr = thr;
	memcpy(wc->u.work, work_in, sizeof(*work_in));

	/* send solution to workio thread */
	if (!tq_push(thr_info[work_thr_id].q, wc))
		goto err_out;

	return true;

err_out:
	workio_cmd_free(wc);
	return false;
}

static void stratum_gen_work(struct stratum_ctx *sctx, struct work *work)
{
	pthread_mutex_lock(&sctx->work_lock);
	/* make headhash and target*/
    memcpy(work->hash,sctx->job.headhash,32);
    memcpy(work->target,sctx->job.target,TARGETLEN); 	
	pthread_mutex_unlock(&sctx->work_lock);
}

static void *miner_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	int thr_id = mythr->id;
	struct work work;
	char s[16];
	uint64_t end_nonce = 0xffffffffffffffffull;
	uint64_t start_nonce = end_nonce / opt_n_threads * thr_id;
	uint64_t max_nonce = end_nonce;
	//uint64_t max_nonce = start_nonce + end_nonce / opt_n_threads;
	//if (opt_n_threads == thr_id + 1) {
	//	max_nonce = end_nonce;
	//}

	/* Set worker threads to nice 19 and then preferentially to SCHED_IDLE
	 * and if that fails, then SCHED_BATCH. No need for this to be an
	 * error if it fails */
	if (!opt_benchmark) {
		setpriority(PRIO_PROCESS, 0, 19);
		drop_policy();
	}

	/* Cpu affinity only makes sense if the number of threads is a multiple
	 * of the number of CPUs */
	if (num_processors > 1 && opt_n_threads % num_processors == 0) {
		if (!opt_quiet)
			applog(LOG_INFO, "Binding thread %d to cpu %d",
			       thr_id, thr_id % num_processors);
		affine_to_cpu(thr_id, thr_id % num_processors);
	}
	
	while (running) {
		uint64_t hashes_done;
		struct timeval tv_start, tv_end, diff;

		// get work
		while (!g_work.done || time(NULL) >= g_work_time + 120) { sleep(1); }

		pthread_mutex_lock(&g_work_lock);
		stratum_gen_work(&stratum, &g_work);
		if (memcmp(work.hash, g_work.hash, 32)) {
			memcpy(&work, &g_work, sizeof(struct work));
		} 
		pthread_mutex_unlock(&g_work_lock);

		if (work.done) {
			if (!work.submit) {
				work.submit = submit_work(mythr, &work);
			}
			sleep(1);
			continue;
		}
		srand((unsigned)time(NULL));
		start_nonce = (uint64_t)rand() * (uint64_t)rand() * 10;
		work_restart[thr_id].restart = 0;	
		work.nonce = start_nonce;
		char *head = bin2hex(work.hash, 32);
		applog(LOG_INFO, "begin miner, thread:%d, headhash:%s,nonce:%llu",thr_id, head, work.nonce);
		

		hashes_done = 0;
		gettimeofday(&tv_start, NULL);

		/* scan nonces for a proof-of-work hash */
		int rc = scanhash_sha512(thr_id,_ds.dataset,_ds.len,work.hash,work.target,
                                work.mixHash,&work.nonce,max_nonce,&hashes_done);

		/* record scanhash elapsed time */
		gettimeofday(&tv_end, NULL);
		timeval_subtract(&diff, &tv_end, &tv_start);
		if (diff.tv_usec || diff.tv_sec) {
			pthread_mutex_lock(&stats_lock);
			thr_hashrates[thr_id] =
				hashes_done / (diff.tv_sec + 1e-6 * diff.tv_usec);
			pthread_mutex_unlock(&stats_lock);
		}
		if (!opt_quiet) {
			sprintf(s, thr_hashrates[thr_id] >= 1e6 ? "%.0f" : "%.2f",
				1e-3 * thr_hashrates[thr_id]);
			applog(LOG_INFO, "thread %d: %lu hashes, %s khash/s",
				thr_id, hashes_done, s);
		}
		if (opt_benchmark && thr_id == opt_n_threads - 1) {
			double hashrate = 0.;
			int i;
			for (i = 0; i < opt_n_threads && thr_hashrates[i]; i++)
				hashrate += thr_hashrates[i];
			if (i == opt_n_threads) {
				sprintf(s, hashrate >= 1e6 ? "%.0f" : "%.2f", 1e-3 * hashrate);
				applog(LOG_INFO, "Total: %s khash/s", s);
			}
		}
		/* if nonce found, submit work */
		if (rc && !opt_benchmark) {
			restart_threads();
			work.submit = submit_work(mythr, &work);
			applog(LOG_INFO, "end miner,thread:%d, headhash:%s,nonce:%llu",thr_id, head,work.nonce);
			g_work.done = true;
			work.done = true;
		}
		free(head);
	}

out:
	tq_freeze(mythr->q);
	return NULL;
}

static bool stratum_handle_response(char *buf)
{
	json_t *val, *err_val, *res_val, *id_val;
	json_error_t err;
	bool ret = false;

	val = JSON_LOADS(buf, &err);
	if (!val) {
		applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");
	id_val = json_object_get(val, "id");

	if (!id_val || json_is_null(id_val) || !res_val)
		goto out;

	share_result(json_is_true(res_val),
		err_val ? json_string_value(json_array_get(err_val, 1)) : NULL);

	ret = true;
out:
	if (val)
		json_decref(val);

	return ret;
}

static void *stratum_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	char *s;

	stratum.url = tq_pop(mythr->q, NULL);
	if (!stratum.url)
		goto out;
	applog(LOG_INFO, "Starting Stratum on %s", stratum.url);

	while (running) {
		int failures = 0;

		while (!stratum.curl) {
			pthread_mutex_lock(&g_work_lock);
			g_work_time = 0;
			pthread_mutex_unlock(&g_work_lock);
			restart_threads();

			if (!stratum_connect(&stratum, stratum.url) ||
				!stratum_authorize(&stratum, coin_base,rpc_user,mail)) {
				stratum_disconnect(&stratum);
				if (opt_retries >= 0 && ++failures > opt_retries) {
					applog(LOG_ERR, "...terminating workio thread");
					tq_push(thr_info[work_thr_id].q, NULL);
					goto out;
				}
				applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
				sleep(opt_fail_pause);
			}
			applog(LOG_INFO, "Stratum authentication success,will be request get_Work");
			stratum_request_work(&stratum);
		}

        if (!empty_hash(stratum.job.seedhash) && !match_ds_hash(stratum.job.seedhash)) {
            // update dataset
			uint8_t seeds[OFF_CYCLE_LEN + SKIP_CYCLE_LEN][16] = { 0 };
			unsigned char seedhash[32] = { 0 };
            if (!stratum_update_dataset(&stratum, stratum.job.seedhash,seeds,seedhash)) {
                applog(LOG_INFO, "Stratum update dataset failed....will be retry.");
            } else {
                // make new dataset before stop all miner
                if (wait_stop_use_dataset()) {
                    _ds.dataset = updateLookupTBL(seeds,_ds.dataset,_ds.len);
					//_ds.dataset = updateLookupTBL((uint8_t(*)[32])seeds, _ds.dataset, _ds.len);
                    dataset_hash(_ds.seedhash,_ds.dataset,_ds.len);
                    update_use_dataset();
					if (!match_ds_hash(seedhash)) {
						applog(LOG_ERR, "stratum_update_dataset NOT match");
						check_seed_head_hash(seeds);
					}
                }
            }           
        }

        // keep update dataset already
		if ((!empty_hash(stratum.job.seedhash) && match_ds_hash(stratum.job.seedhash)) &&
		    (strcmp(stratum.job.headhash, g_work.hash) || !g_work_time)) {
			pthread_mutex_lock(&g_work_lock);
			stratum_gen_work(&stratum, &g_work);
			g_work.done = false;
			time(&g_work_time);
			pthread_mutex_unlock(&g_work_lock);
			if (stratum.job.clean) {
				applog(LOG_INFO, "Stratum detected new block");
				restart_threads();
			}
		}
		
		if (!stratum_socket_full(&stratum, 600)) {
			applog(LOG_ERR, "Stratum connection timed out");
			s = NULL;
		} else
			s = stratum_recv_line(&stratum);
		if (!s) {
			stratum_disconnect(&stratum);
			applog(LOG_ERR, "Stratum connection interrupted");
			continue;
		}
		if (!stratum_handle_method(&stratum, s))
			stratum_handle_response(s);
		free(s);
	}

out:
	return NULL;
}

static void show_version_and_exit(void)
{
	printf("%s\n%s\n", PACKAGE_STRING, curl_version());
	exit(0);
}

static void show_usage_and_exit(int status)
{
	if (status)
		fprintf(stderr, "Try `" PROGRAM_NAME " --help' for more information.\n");
	else
		printf(usage);
	exit(status);
}

static void parse_arg (int key, char *arg)
{
	char *p;
	int v, i;

	switch(key) {
	case 'B':
		opt_background = true;
		break;
	case 'c': {
		json_error_t err;
		if (opt_config)
			json_decref(opt_config);
#if JANSSON_VERSION_HEX >= 0x020000
		opt_config = json_load_file(arg, 0, &err);
#else
		opt_config = json_load_file(arg, &err);
#endif
		if (!json_is_object(opt_config)) {
			applog(LOG_ERR, "JSON decode of %s failed", arg);
			exit(1);
		}
		break;
	}
	case 'q':
		opt_quiet = true;
		break;
	case 'D':
		opt_debug = true;
		break;
	case 'm':
		free(mail);
		mail = strdup(arg);
		break;
	case 'P':
		opt_protocol = true;
		break;
	case 'r':
		v = atoi(arg);
		if (v < -1 || v > 9999)	/* sanity check */
			show_usage_and_exit(1);
		opt_retries = v;
		break;
	case 'R':
		v = atoi(arg);
		if (v < 1 || v > 9999)	/* sanity check */
			show_usage_and_exit(1);
		opt_fail_pause = v;
		break;
	case 'T':
		v = atoi(arg);
		if (v < 1 || v > 99999)	/* sanity check */
			show_usage_and_exit(1);
		opt_timeout = v;
		break;
	case 't':
		v = atoi(arg);
		if (v < 1 || v > 9999)	/* sanity check */
			show_usage_and_exit(1);
		opt_n_threads = v;
		break;
	case 'u':
		free(rpc_user);
		rpc_user = strdup(arg);
		break;
	case 'o':			/* --url */
		p = strstr(arg, "://");
		if (p) {
			if (strncasecmp(arg, "http://", 7) && strncasecmp(arg, "https://", 8) &&
					strncasecmp(arg, "stratum+tcp://", 14))
				show_usage_and_exit(1);
			free(rpc_url);
			rpc_url = strdup(arg);
		} else {
			if (!strlen(arg) || *arg == '/')
				show_usage_and_exit(1);
			free(rpc_url);
			rpc_url = malloc(strlen(arg) + 8);
			sprintf(rpc_url, "http://%s", arg);
		}
		have_stratum = !opt_benchmark && !strncasecmp(rpc_url, "stratum", 7);
		break;
	case 'C':			/* --coinbase*/
		free(coin_base);
		coin_base = strdup(arg);
		if (34 != strlen(coin_base))
			show_usage_and_exit(1);
		break;
	case 'x':			/* --proxy */
		if (!strncasecmp(arg, "socks4://", 9))
			opt_proxy_type = CURLPROXY_SOCKS4;
		else if (!strncasecmp(arg, "socks5://", 9))
			opt_proxy_type = CURLPROXY_SOCKS5;
#if LIBCURL_VERSION_NUM >= 0x071200
		else if (!strncasecmp(arg, "socks4a://", 10))
			opt_proxy_type = CURLPROXY_SOCKS4A;
		else if (!strncasecmp(arg, "socks5h://", 10))
			opt_proxy_type = CURLPROXY_SOCKS5_HOSTNAME;
#endif
		else
			opt_proxy_type = CURLPROXY_HTTP;
		free(opt_proxy);
		opt_proxy = strdup(arg);
		break;
	case 1001:
		free(opt_cert);
		opt_cert = strdup(arg);
		break;
	case 1005:
		opt_benchmark = true;
		want_stratum = false;
		have_stratum = false;
		break;
	case 'S':
		use_syslog = true;
		break;
	case 'V':
		show_version_and_exit();
	case 'h':
		show_usage_and_exit(0);
	default:
		show_usage_and_exit(1);
	}
}

static void parse_config(void)
{
	int i;
	json_t *val;

	if (!json_is_object(opt_config))
		return;

	for (i = 0; i < ARRAY_SIZE(options); i++) {
		if (!options[i].name)
			break;
		if (!strcmp(options[i].name, "config"))
			continue;

		val = json_object_get(opt_config, options[i].name);
		if (!val)
			continue;

		if (options[i].has_arg && json_is_string(val)) {
			char *s = strdup(json_string_value(val));
			if (!s)
				break;
			parse_arg(options[i].val, s);
			free(s);
		} else if (!options[i].has_arg && json_is_true(val))
			parse_arg(options[i].val, "");
		else
			applog(LOG_ERR, "JSON option %s invalid",
				options[i].name);
	}
}

static void parse_cmdline(int argc, char *argv[])
{
	int key;

	while (1) {
#if HAVE_GETOPT_LONG
		key = getopt_long(argc, argv, short_options, options, NULL);
#else
		key = getopt(argc, argv, short_options);
#endif
		if (key < 0)
			break;

		parse_arg(key, optarg);
	}
	if (optind < argc) {
		fprintf(stderr, "%s: unsupported non-option argument '%s'\n",
			argv[0], argv[optind]);
		show_usage_and_exit(1);
	}

	parse_config();
}

#ifndef WIN32
void signal_handler(int sig)
{
	switch (sig) {
	case SIGHUP:
		applog(LOG_INFO, "SIGHUP received");
		break;
	case SIGINT:
		applog(LOG_INFO, "SIGINT received, exiting");
		exit(0);
		break;
	case SIGTERM:
		applog(LOG_INFO, "SIGTERM received, exiting");
		exit(0);
		break;
	}
}
#endif

int main(int argc, char *argv[])
{
	struct thr_info *thr;
	long flags;
	int i;
	
	rpc_url = strdup(DEF_RPC_URL);
	rpc_user = strdup("admin");
	coin_base = "0xb85150eb365e7df0941f0cf08235f987ba91506a";
	mail = "123@126.com";
	/* parse command line */
	parse_cmdline(argc, argv);

	pthread_mutex_init(&applog_lock, NULL);
	pthread_mutex_init(&stats_lock, NULL);
	pthread_mutex_init(&g_work_lock, NULL);
	pthread_mutex_init(&stratum.sock_lock, NULL);
	pthread_mutex_init(&stratum.work_lock, NULL);
	memset(&stratum.job, 0, sizeof(stratum.job));

	applog(LOG_INFO, "true-miner start...");

	flags = strncmp(rpc_url, "https:", 6)
	      ? (CURL_GLOBAL_ALL & ~CURL_GLOBAL_SSL)
	      : CURL_GLOBAL_ALL;
	if (curl_global_init(flags)) {
		applog(LOG_ERR, "CURL initialization failed");
		return 1;
	}

#ifndef WIN32
	if (opt_background) {
		i = fork();
		if (i < 0) exit(1);
		if (i > 0) exit(0);
		i = setsid();
		if (i < 0)
			applog(LOG_ERR, "setsid() failed (errno = %d)", errno);
		i = chdir("/");
		if (i < 0)
			applog(LOG_ERR, "chdir() failed (errno = %d)", errno);
		signal(SIGHUP, signal_handler);
		signal(SIGINT, signal_handler);
		signal(SIGTERM, signal_handler);
	}
#endif

#if defined(WIN32)
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	num_processors = sysinfo.dwNumberOfProcessors;
#elif defined(_SC_NPROCESSORS_CONF)
	num_processors = sysconf(_SC_NPROCESSORS_CONF);
#elif defined(HW_NCPU)
	int req[] = { CTL_HW, HW_NCPU };
	size_t len = sizeof(num_processors);
	v = sysctl(req, 2, &num_processors, &len, NULL, 0);
#else
	num_processors = 1;
#endif
	if (num_processors < 1)
		num_processors = 1;
	if (!opt_n_threads)
		opt_n_threads = num_processors;

#ifdef HAVE_SYSLOG_H
	if (use_syslog)
		openlog("cpuminer", LOG_PID, LOG_USER);
#endif
	opt_n_threads = 1;
	work_restart = calloc(opt_n_threads, sizeof(*work_restart));
	if (!work_restart)
		return 1;
    for (int i=0;i<opt_n_threads;i++) work_restart[i].stopped = 1;
    
	thr_info = calloc(opt_n_threads + 2, sizeof(*thr));
	if (!thr_info)
		return 1;
	
	thr_hashrates = (double *) calloc(opt_n_threads, sizeof(double));
	if (!thr_hashrates)
		return 1;
	//test_minerva();
    init_dataset();
	//char *seedhash = bin2hex(_ds.seedhash, 32);
	//applog(LOG_INFO, "first current dataset_hash:%s", seedhash);
	//free(seedhash);
	/* init workio thread info */
	work_thr_id = opt_n_threads;
	thr = &thr_info[work_thr_id];
	thr->id = work_thr_id;
	thr->q = tq_new();
	if (!thr->q)
		return 1;

	/* start work I/O thread */
	if (pthread_create(&thr->pth, NULL, workio_thread, thr)) {
		applog(LOG_ERR, "workio thread create failed");
		return 1;
	}

	if (want_stratum) {
		/* init stratum thread info */
		stratum_thr_id = opt_n_threads + 1;
		thr = &thr_info[stratum_thr_id];
		thr->id = stratum_thr_id;
		thr->q = tq_new();
		if (!thr->q)
			return 1;

		/* start stratum thread */
		if (unlikely(pthread_create(&thr->pth, NULL, stratum_thread, thr))) {
			applog(LOG_ERR, "stratum thread create failed");
			return 1;
		}

		if (have_stratum)
			tq_push(thr_info[stratum_thr_id].q, strdup(rpc_url));
	}

	/* start mining threads */
	for (i = 0; i < opt_n_threads; i++) {
		thr = &thr_info[i];

		thr->id = i;
		thr->q = tq_new();
		if (!thr->q)
			return 1;

		if (unlikely(pthread_create(&thr->pth, NULL, miner_thread, thr))) {
			applog(LOG_ERR, "thread %d create failed", i);
			return 1;
		}
	}

	applog(LOG_INFO, "%d miner threads started, "
		"using algorithm=minerva.",opt_n_threads);

	/* main loop - simply wait for workio thread to exit */
	pthread_join(thr_info[work_thr_id].pth, NULL);
	running = false;
	applog(LOG_INFO, "workio thread dead, exiting.");
    free_dataset();
	return 0;
}
