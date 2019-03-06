
if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

EXTRA_DIST	= example-cfg.json nomacro.pl

SUBDIRS		= compat

bin_PROGRAMS	= tminerd

tminerd_SOURCES	= elist.h miner.h compat.h sha3.h sha3_256.h \
		  cpu-miner.c util.c minerva.c sha3.c sha3_256.c
		  
tminerd_LDFLAGS	= $(PTHREAD_FLAGS)
tminerd_LDADD	= @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@
tminerd_CFLAGS	= -fno-strict-aliasing
tminerd_CPPFLAGS	= @LIBCURL_CPPFLAGS@ $(JANSSON_INCLUDES) $(PTHREAD_FLAGS)
