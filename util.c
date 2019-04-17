/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#define _GNU_SOURCE
#include "cpuminer-config.h"
#include "miner.h"
#include "elist.h"



struct upload_buffer {
	const void	*buf;
	size_t		len;
	size_t		pos;
};

struct header_info {
	char		*lp_path;
	char		*reason;
	char		*stratum_url;
};

struct tq_ent {
	void			*data;
	struct list_head	q_node;
};

struct thread_q {
	struct list_head	q;

	bool frozen;

	pthread_mutex_t		mutex;
	pthread_cond_t		cond;
};

void applog(int prio, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

#ifdef HAVE_SYSLOG_H
	if (use_syslog) {
		va_list ap2;
		char *buf;
		int len;
		
		va_copy(ap2, ap);
		len = vsnprintf(NULL, 0, fmt, ap2) + 1;
		va_end(ap2);
		buf = alloca(len);
		if (vsnprintf(buf, len, fmt, ap) >= 0)
			syslog(prio, "%s", buf);
	}
#else
	if (0) {}
#endif
	else {
		char *f;
		int len;
		time_t now;
		struct tm tm, *tm_p;

		time(&now);

		pthread_mutex_lock(&applog_lock);
		tm_p = localtime(&now);
		memcpy(&tm, tm_p, sizeof(tm));
		pthread_mutex_unlock(&applog_lock);

		len = 40 + strlen(fmt) + 2;
		f = alloca(len);
		sprintf(f, "[%d-%02d-%02d %02d:%02d:%02d] %s\n",
			tm.tm_year + 1900,
			tm.tm_mon + 1,
			tm.tm_mday,
			tm.tm_hour,
			tm.tm_min,
			tm.tm_sec,
			fmt);
		pthread_mutex_lock(&applog_lock);
		vfprintf(stderr, f, ap);	/* atomic write to stderr */
		fflush(stderr);
		pthread_mutex_unlock(&applog_lock);
	}
	va_end(ap);
}

#if LIBCURL_VERSION_NUM >= 0x071200
static int seek_data_cb(void *user_data, curl_off_t offset, int origin)
{
	struct upload_buffer *ub = user_data;
	
	switch (origin) {
	case SEEK_SET:
		ub->pos = offset;
		break;
	case SEEK_CUR:
		ub->pos += offset;
		break;
	case SEEK_END:
		ub->pos = ub->len + offset;
		break;
	default:
		return 1; /* CURL_SEEKFUNC_FAIL */
	}

	return 0; /* CURL_SEEKFUNC_OK */
}
#endif

#if LIBCURL_VERSION_NUM >= 0x070f06
static int sockopt_keepalive_cb(void *userdata, curl_socket_t fd,curlsocktype purpose)
{
	int keepalive = 1;
	int tcp_keepcnt = 3;
	int tcp_keepidle = 50;
	int tcp_keepintvl = 50;

#ifndef WIN32
	if (unlikely(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive,
		sizeof(keepalive))))
		return 1;
#ifdef __linux
	if (unlikely(setsockopt(fd, SOL_TCP, TCP_KEEPCNT,
		&tcp_keepcnt, sizeof(tcp_keepcnt))))
		return 1;
	if (unlikely(setsockopt(fd, SOL_TCP, TCP_KEEPIDLE,
		&tcp_keepidle, sizeof(tcp_keepidle))))
		return 1;
	if (unlikely(setsockopt(fd, SOL_TCP, TCP_KEEPINTVL,
		&tcp_keepintvl, sizeof(tcp_keepintvl))))
		return 1;
#endif /* __linux */
#ifdef __APPLE_CC__
	if (unlikely(setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE,
		&tcp_keepintvl, sizeof(tcp_keepintvl))))
		return 1;
#endif /* __APPLE_CC__ */
#else /* WIN32 */
	struct tcp_keepalive vals;
	vals.onoff = 1;
	vals.keepalivetime = tcp_keepidle * 1000;
	vals.keepaliveinterval = tcp_keepintvl * 1000;
	DWORD outputBytes;
	if (unlikely(WSAIoctl(fd, SIO_KEEPALIVE_VALS, &vals, sizeof(vals),
		NULL, 0, &outputBytes, NULL, NULL)))
		return 1;
#endif /* WIN32 */

	return 0;
}
#endif

char *bin2hex(const unsigned char *p, size_t len)
{
	int i;
	char *s = malloc((len * 2) + 1);
	if (!s)
		return NULL;

	for (i = 0; i < len; i++)
		sprintf(s + (i * 2), "%02x", (unsigned int) p[i]);

	return s;
}

bool hex2bin(unsigned char *p, const char *hexstr, size_t len)
{
	char hex_byte[3];
	char *ep;

	hex_byte[2] = '\0';
	if (hexstr[0] == '0' && (hexstr[1] == 'x' || hexstr[1] == 'X')) {
		hexstr += 2;
	}
	while (*hexstr && len) {
		if (!hexstr[1]) {
			applog(LOG_ERR, "hex2bin str truncated");
			return false;
		}
		hex_byte[0] = hexstr[0];
		hex_byte[1] = hexstr[1];
		*p = (unsigned char) strtol(hex_byte, &ep, 16);
		if (*ep) {
			applog(LOG_ERR, "hex2bin failed on '%s'", hex_byte);
			return false;
		}
		p++;
		hexstr += 2;
		len--;
	}

	return (len == 0 && *hexstr == 0) ? true : false;
}

/* Subtract the `struct timeval' values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0.  */
int timeval_subtract(struct timeval *result, struct timeval *x,struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating Y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	 * `tv_usec' is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}


#ifdef WIN32
#define socket_blocks() (WSAGetLastError() == WSAEWOULDBLOCK)
#else
#define socket_blocks() (errno == EAGAIN || errno == EWOULDBLOCK)
#endif

static bool send_line(curl_socket_t sock, char *s)
{
	ssize_t len, sent = 0;
	
	len = strlen(s);
	s[len++] = '\n';

	while (len > 0) {
		struct timeval timeout = {0, 0};
		ssize_t n;
		fd_set wd;

		FD_ZERO(&wd);
		FD_SET(sock, &wd);
		if (select(sock + 1, NULL, &wd, NULL, &timeout) < 1)
			return false;
		n = send(sock, s + sent, len, 0);
		if (n < 0) {
			if (!socket_blocks())
				return false;
			n = 0;
		}
		sent += n;
		len -= n;
	}

	return true;
}

bool stratum_send_line(struct stratum_ctx *sctx, char *s)
{
	bool ret = false;

	if (opt_protocol)
		applog(LOG_DEBUG, "> %s", s);

	pthread_mutex_lock(&sctx->sock_lock);
	ret = send_line(sctx->sock, s);
	pthread_mutex_unlock(&sctx->sock_lock);

	return ret;
}

static bool socket_full(curl_socket_t sock, int timeout)
{
	struct timeval tv;
	fd_set rd;

	FD_ZERO(&rd);
	FD_SET(sock, &rd);
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	if (select(sock + 1, &rd, NULL, NULL, &tv) > 0)
		return true;
	return false;
}

bool stratum_socket_full(struct stratum_ctx *sctx, int timeout)
{
	return strlen(sctx->sockbuf) || socket_full(sctx->sock, timeout);
}

#define RBUFSIZE 2048
#define RECVSIZE (RBUFSIZE - 4)

static void stratum_buffer_append(struct stratum_ctx *sctx, const char *s)
{
	size_t old, new;

	old = strlen(sctx->sockbuf);
	new = old + strlen(s) + 1;
	if (new >= sctx->sockbuf_size) {
		sctx->sockbuf_size = new + (RBUFSIZE - (new % RBUFSIZE));
		sctx->sockbuf = realloc(sctx->sockbuf, sctx->sockbuf_size);
	}
	strcpy(sctx->sockbuf + old, s);
}

char *stratum_recv_line(struct stratum_ctx *sctx)
{
	ssize_t len, buflen;
	char *tok, *sret = NULL;

	if (!strstr(sctx->sockbuf, "\n")) {
		bool ret = true;
		time_t rstart;

		time(&rstart);
		if (!socket_full(sctx->sock, 60)) {
			applog(LOG_ERR, "stratum_recv_line timed out");
			goto out;
		}
		do {
			char s[RBUFSIZE];
			ssize_t n;

			memset(s, 0, RBUFSIZE);
			n = recv(sctx->sock, s, RECVSIZE, 0);
			if (!n) {
				ret = false;
				break;
			}
			if (n < 0) {
				if (!socket_blocks() || !socket_full(sctx->sock, 1)) {
					ret = false;
					break;
				}
			} else
				stratum_buffer_append(sctx, s);
		} while (time(NULL) - rstart < 60 && !strstr(sctx->sockbuf, "\n"));

		if (!ret) {
			applog(LOG_ERR, "stratum_recv_line failed");
			goto out;
		}
	}

	buflen = strlen(sctx->sockbuf);
	tok = strtok(sctx->sockbuf, "\n");
	if (!tok) {
		applog(LOG_ERR, "stratum_recv_line failed to parse a newline-terminated string");
		goto out;
	}
	sret = strdup(tok);
	len = strlen(sret);

	if (buflen > len + 1)
		memmove(sctx->sockbuf, sctx->sockbuf + len + 1, buflen - len + 1);
	else
		sctx->sockbuf[0] = '\0';

out:
	if (sret && opt_protocol)
		applog(LOG_DEBUG, "< %s", sret);
	return sret;
}

#if LIBCURL_VERSION_NUM >= 0x071101
static curl_socket_t opensocket_grab_cb(void *clientp, curlsocktype purpose,
	struct curl_sockaddr *addr)
{
	curl_socket_t *sock = clientp;
	*sock = socket(addr->family, addr->socktype, addr->protocol);
	return *sock;
}
#endif

bool stratum_connect(struct stratum_ctx *sctx, const char *url)
{
	CURL *curl;
	int rc;

	pthread_mutex_lock(&sctx->sock_lock);
	if (sctx->curl)
		curl_easy_cleanup(sctx->curl);
	sctx->curl = curl_easy_init();
	if (!sctx->curl) {
		applog(LOG_ERR, "CURL initialization failed");
		pthread_mutex_unlock(&sctx->sock_lock);
		return false;
	}
	curl = sctx->curl;
	if (!sctx->sockbuf) {
		sctx->sockbuf = calloc(RBUFSIZE, 1);
		sctx->sockbuf_size = RBUFSIZE;
	}
	sctx->sockbuf[0] = '\0';
	pthread_mutex_unlock(&sctx->sock_lock);

	if (url != sctx->url) {
		free(sctx->url);
		sctx->url = strdup(url);
	}
	if (!sctx->curl_url)
		free(sctx->curl_url);
	sctx->curl_url = malloc(strlen(url));
	sprintf(sctx->curl_url, "http%s", strstr(url, "://"));

	if (opt_protocol)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, sctx->curl_url);
	curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, sctx->curl_err_str);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
	if (opt_proxy && opt_proxy_type != CURLPROXY_HTTP) {
		curl_easy_setopt(curl, CURLOPT_PROXY, opt_proxy);
		curl_easy_setopt(curl, CURLOPT_PROXYTYPE, opt_proxy_type);
	} else if (getenv("http_proxy")) {
		if (getenv("all_proxy"))
			curl_easy_setopt(curl, CURLOPT_PROXY, getenv("all_proxy"));
		else if (getenv("ALL_PROXY"))
			curl_easy_setopt(curl, CURLOPT_PROXY, getenv("ALL_PROXY"));
		else
			curl_easy_setopt(curl, CURLOPT_PROXY, "");
	}
#if LIBCURL_VERSION_NUM >= 0x070f06
	curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_keepalive_cb);
#endif
#if LIBCURL_VERSION_NUM >= 0x071101
	curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, opensocket_grab_cb);
	curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &sctx->sock);
#endif
	curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1);

	rc = curl_easy_perform(curl);
	if (rc) {
		applog(LOG_ERR, "Stratum connection failed: %s", sctx->curl_err_str);
		curl_easy_cleanup(curl);
		sctx->curl = NULL;
		return false;
	}

#if LIBCURL_VERSION_NUM < 0x071101
	/* CURLINFO_LASTSOCKET is broken on Win64; only use it as a last resort */
	curl_easy_getinfo(curl, CURLINFO_LASTSOCKET, (long *)&sctx->sock);
#endif

	return true;
}

void stratum_disconnect(struct stratum_ctx *sctx)
{
	pthread_mutex_lock(&sctx->sock_lock);
	if (sctx->curl) {
		curl_easy_cleanup(sctx->curl);
		sctx->curl = NULL;
		sctx->sockbuf[0] = '\0';
	}
	pthread_mutex_unlock(&sctx->sock_lock);
}

void stratum_request_work(struct stratum_ctx *sctx) {
	char tmp[200] = { 0 };
	const char *s = "{\"id\": 2, \"method\": \"etrue_getWork\"}";
	memcpy(tmp, s, strlen(s));
	if (!stratum_send_line(sctx, tmp)){
		applog(LOG_ERR, "send stratum_request_work failed");
	}
}
bool stratum_authorize(struct stratum_ctx *sctx, const char *coinbase, const char *user, const char* mail)
{
	json_t *val = NULL, *res_val, *err_val;
	char *s, *sret;
	json_error_t err;
	bool ret = false;
	int sum = 200 + strlen(coinbase);
	if (user != NULL){
		sum += strlen(user);
	}
	if (mail != NULL){
		sum += strlen(mail);
	}
	s = calloc(sum,1);
	char tmp[256] = { 0 };
	int pos = 0;
	sprintf(tmp, "{\"id\": 1,\"jsonrpc\": \"2.0\", \"method\": \"etrue_submitLogin\", \"params\": [\"%s\"",coinbase);
	memcpy(s,tmp,strlen(tmp));
	pos += strlen(tmp);
	memset(tmp, 0, sizeof(tmp));
	if (mail != NULL) {
		sprintf(tmp, ",\"%s\"]", mail);
	}
	else {
		sprintf(tmp, "%c,", ']');
	}
	memcpy(s+pos, tmp, strlen(tmp));
	pos += strlen(tmp);
	memset(tmp, 0, sizeof(tmp));
	if (user != NULL) {
		sprintf(tmp, ",\"worker\":\"%s\"}", user);
	}
	else {
		sprintf(tmp, "%c", '}');
	}
	memcpy(s +pos, tmp, strlen(tmp));
	pos += strlen(tmp);

	if (!stratum_send_line(sctx, s))
		goto out;

	while (1) {
		sret = stratum_recv_line(sctx);
		if (!sret)
			goto out;
		if (!stratum_handle_method(sctx, sret))
			break;
		free(sret);
	}

	val = JSON_LOADS(sret, &err);
	free(sret);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");

	if (!res_val || json_is_false(res_val) ||
	    (err_val && !json_is_null(err_val)))  {
		applog(LOG_ERR, "Stratum authentication failed");
		goto out;
	}

	ret = true;

out:
	free(s);
	if (val)
		json_decref(val);

	return ret;
}
bool stratum_submit(json_t *val) {
	json_t *err_val = json_object_get(val, "error");
	char head[67] = { 0 };
	// make sure thread-safe
	get_work_id(head);
	if (err_val && !json_is_null(err_val)) {
		int code = json_integer_value(json_object_get(err_val, "code"));
		char *errstr = json_string_value(json_object_get(err_val, "message"));
		applog(LOG_ERR, "etrue_submit,code:%d,msg:%s,headhash:%s", code, errstr,head);
		return false;
	}
	json_t *res_val = json_object_get(val, "result");
	if (!res_val || json_is_false(res_val)) {
		applog(LOG_ERR, "etrue_submit,headhash:%s,result:false", head);
		return false;
	}
	applog(LOG_ERR, "etrue_submit,headhash:%s,result:true", head);
	return true;
}

static bool stratum_notify(struct stratum_ctx *sctx, json_t *params)
{
	const char *seedhash,*headhash,*target;
	bool ret = false;

	headhash = json_string_value(json_array_get(params, 0));
	seedhash = json_string_value(json_array_get(params, 1));
	target = json_string_value(json_array_get(params, 2));

	if (!seedhash || !headhash || !target ||
	    strlen(seedhash) != 66 || strlen(headhash) != 66 || 
		strlen(target) != 34) {
		applog(LOG_ERR, "Stratum notify: invalid parameters");
		goto out;
	}

	pthread_mutex_lock(&sctx->work_lock);
	hex2bin(sctx->job.seedhash, seedhash, 66);
	hex2bin(sctx->job.headhash, headhash, 66);
	hex2bin(sctx->job.target, target, 34);
	sctx->job.clean = true;
	sctx->job.new_work = true;
	pthread_mutex_unlock(&sctx->work_lock);

	ret = true;
	applog(LOG_INFO, "handle notify,target:%s,seedhash:%s,headhash:%s,",target, seedhash, headhash);

out:
	return ret;
}

static bool stratum_reconnect(struct stratum_ctx *sctx, json_t *params)
{
	json_t *port_val;
	const char *host;
	int port;

	host = json_string_value(json_array_get(params, 0));
	port_val = json_array_get(params, 1);
	if (json_is_string(port_val))
		port = atoi(json_string_value(port_val));
	else
		port = json_integer_value(port_val);
	if (!host || !port)
		return false;
	
	free(sctx->url);
	sctx->url = malloc(32 + strlen(host));
	sprintf(sctx->url, "stratum+tcp://%s:%d", host, port);

	applog(LOG_NOTICE, "Server requested reconnection to %s", sctx->url);

	stratum_disconnect(sctx);

	return true;
}

static bool stratum_get_version(struct stratum_ctx *sctx, json_t *id)
{
	char *s;
	json_t *val;
	bool ret;
	
	if (!id || json_is_null(id))
		return false;

	val = json_object();
	json_object_set(val, "id", id);
	json_object_set_new(val, "error", json_null());
	json_object_set_new(val, "result", json_string(USER_AGENT));
	s = json_dumps(val, 0);
	ret = stratum_send_line(sctx, s);
	json_decref(val);
	free(s);

	return ret;
}
static bool stratum_get_hashrate(struct stratum_ctx *sctx, json_t *id)
{
	char *s;
	json_t *val;
	bool ret;

	if (!id || json_is_null(id))
		return false;

	val = json_object();
	json_object_set(val, "id", id);
	json_object_set_new(val, "error", json_null());
	json_object_set_new(val, "method", json_string("etrue_get_hashrate"));
	char rate[256] = { 0 };
	get_hashrate(rate);
	json_object_set_new(val, "result", json_string(rate));
	s = json_dumps(val, 0);
	ret = stratum_send_line(sctx, s);
	json_decref(val);
	free(s);

	return ret;
}
static bool stratum_show_message(struct stratum_ctx *sctx, json_t *id, json_t *params)
{
	char *s;
	json_t *val;
	bool ret;

	val = json_array_get(params, 0);
	if (val)
		applog(LOG_NOTICE, "MESSAGE FROM SERVER: %s", json_string_value(val));
	
	if (!id || json_is_null(id))
		return true;

	val = json_object();
	json_object_set(val, "id", id);
	json_object_set_new(val, "error", json_null());
	json_object_set_new(val, "result", json_true());
	s = json_dumps(val, 0);
	ret = stratum_send_line(sctx, s);
	json_decref(val);
	free(s);

	return ret;
}
bool stratum_update_dataset(struct stratum_ctx *sctx, const char *curseedhash, uint8_t seeds[OFF_CYCLE_LEN + SKIP_CYCLE_LEN][16], unsigned char seedhash[32])
{
	json_t *val = NULL, *res_val, *err_val,*seeds_val;
	char *s, *sret;
	json_error_t err;
	bool ret = false;

	s = malloc(80 + strlen(curseedhash));
	sprintf(s, "{\"id\": 4, \"method\": \"etrue_seedhash\", \"params\": [\"%s\"]}",curseedhash);

	if (!stratum_send_line(sctx, s))
		goto out;

	while (1) {
		sret = stratum_recv_line(sctx);
		if (!sret)
			goto out;
		if (!stratum_handle_method(sctx, sret))
			break;
		free(sret);
	}

	val = JSON_LOADS(sret, &err);
	free(sret);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}
	int id = json_integer_value(json_object_get(val,"id"));
	const char *method = json_string_value(json_object_get(val, "method"));
	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");

	if (!res_val || !json_is_array(res_val) || (err_val && !json_is_null(err_val)) || 
		!method || strcasecmp(method, "etrue_seedhash") || id != 4)  {
		applog(LOG_ERR, "Stratum update_dataset failed");
		goto out;
	}
	const char *seedhashstr = json_string_value(json_array_get(res_val,1));
	seeds_val = json_array_get(res_val, 0);
	if (NULL == seedhashstr || seeds_val == NULL || strlen(seedhashstr) != 66) goto out;

	unsigned int seed_count = json_array_size(seeds_val);
	if (seed_count != (OFF_CYCLE_LEN + SKIP_CYCLE_LEN)) {
		applog(LOG_ERR, "Stratum update dataset,seed_count error:%d",seed_count);
		goto out;
	}
	for (int i = 0; i < seed_count; i++) {
		const char *ss = json_string_value(json_array_get(seeds_val, i));
		if (!ss || strlen(ss) != 34) {
			while (i--)
			applog(LOG_ERR, "Stratum update dataset: invalid seed_headhash");
			goto out;
		}
		hex2bin(seeds[i], ss, 34);
	}
	hex2bin(seedhash, seedhashstr, 66);
	ret = true;
out:
	free(s);
	if (val)
		json_decref(val);

	return ret;
}

bool stratum_handle_method(struct stratum_ctx *sctx, const char *s)
{
	json_t *val, *result,*err_val;
	json_error_t err;
	const char *method;
	bool ret = false;

	val = JSON_LOADS(s, &err);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}
	int id = json_integer_value(json_object_get(val, "id"));
	result = json_object_get(val, "result");
	if (id == 3) {
		ret = stratum_submit(val);
		goto out;
	}
	err_val = json_object_get(val, "error");

	if (err_val && !json_is_null(err_val)) {
		int code = json_integer_value(json_object_get(err_val, "code"));
		char *errstr = json_string_value(json_object_get(err_val, "message"));
		applog(LOG_ERR, "code:%d,msg:%s",code,errstr);
		goto out;
	}	
	method = json_string_value(json_object_get(val, "method"));
	if (!method) goto out;

	if ((id == 0 && !strcasecmp(method, "etrue_notify")) || !strcasecmp(method, "etrue_getWork")) {
		ret = stratum_notify(sctx, result);
		goto out;
	}
	if (!strcasecmp(method, "etrue_get_version")) {
		ret = stratum_get_version(sctx, id);
		goto out;
	}
	if (!strcasecmp(method, "etrue_get_hashrate")) {
		ret = stratum_get_hashrate(sctx, id);
		goto out;
	}
	// not used
	if (!strcasecmp(method, "client.reconnect")) {
		ret = stratum_reconnect(sctx, result);
		goto out;
	}
	if (!strcasecmp(method, "client.show_message")) {
		ret = stratum_show_message(sctx, id, result);
		goto out;
	}

out:
	if (val)
		json_decref(val);

	return ret;
}

struct thread_q *tq_new(void)
{
	struct thread_q *tq;

	tq = calloc(1, sizeof(*tq));
	if (!tq)
		return NULL;

	INIT_LIST_HEAD(&tq->q);
	pthread_mutex_init(&tq->mutex, NULL);
	pthread_cond_init(&tq->cond, NULL);

	return tq;
}

void tq_free(struct thread_q *tq)
{
	struct tq_ent *ent, *iter;

	if (!tq)
		return;
#ifdef WIN32
	ent = list_entry((&tq->q)->next, struct tq_ent, q_node);
	iter = list_entry(ent->q_node.next, struct tq_ent, q_node);

	for (; &ent->q_node != (&tq->q);
		ent = iter, iter = list_entry(iter->q_node.next, struct tq_ent, q_node)) {

		list_del(&ent->q_node);
		free(ent);
	}
#else
	list_for_each_entry_safe(ent, iter, &tq->q, q_node) {
		list_del(&ent->q_node);
		free(ent);
	}
#endif

	pthread_cond_destroy(&tq->cond);
	pthread_mutex_destroy(&tq->mutex);

	memset(tq, 0, sizeof(*tq));	/* poison */
	free(tq);
}

static void tq_freezethaw(struct thread_q *tq, bool frozen)
{
	pthread_mutex_lock(&tq->mutex);

	tq->frozen = frozen;

	pthread_cond_signal(&tq->cond);
	pthread_mutex_unlock(&tq->mutex);
}

void tq_freeze(struct thread_q *tq)
{
	tq_freezethaw(tq, true);
}

void tq_thaw(struct thread_q *tq)
{
	tq_freezethaw(tq, false);
}

bool tq_push(struct thread_q *tq, void *data)
{
	struct tq_ent *ent;
	bool rc = true;

	ent = calloc(1, sizeof(*ent));
	if (!ent)
		return false;

	ent->data = data;
	INIT_LIST_HEAD(&ent->q_node);

	pthread_mutex_lock(&tq->mutex);

	if (!tq->frozen) {
		list_add_tail(&ent->q_node, &tq->q);
	} else {
		free(ent);
		rc = false;
	}

	pthread_cond_signal(&tq->cond);
	pthread_mutex_unlock(&tq->mutex);

	return rc;
}

void *tq_pop(struct thread_q *tq, const struct timespec *abstime)
{
	struct tq_ent *ent;
	void *rval = NULL;
	int rc;

	pthread_mutex_lock(&tq->mutex);

	if (!list_empty(&tq->q))
		goto pop;

	if (abstime)
		rc = pthread_cond_timedwait(&tq->cond, &tq->mutex, abstime);
	else
		rc = pthread_cond_wait(&tq->cond, &tq->mutex);
	if (rc)
		goto out;
	if (list_empty(&tq->q))
		goto out;

pop:
	ent = list_entry(tq->q.next, struct tq_ent, q_node);
	rval = ent->data;

	list_del(&ent->q_node);
	free(ent);

out:
	pthread_mutex_unlock(&tq->mutex);
	return rval;
}
