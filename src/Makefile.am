securelibdir = $(SECUREDIR)

pam_unix_fprintd_la_CFLAGS = \
	$(GLIB_CFLAGS) \
	-DCHKPWD_HELPER=\"$(sbindir)/unix_chkpwd\" \
	-D"UNUSED"=

if HAVE_LIBSELINUX
	pam_unix_fprintd_la_CFLAGS += \
		-D"WITH_SELINUX"
endif

pam_unix_fprintd_la_LDFLAGS = \
	-no-undefined \
	-avoid-version \
	-module

pam_unix_fprintd_la_LIBADD = \
	-lpam \
	-lpamc \
	-lpthread \
	$(LIBCRYPT) \
	$(LIBSELINUX) \
	$(GLIB_LIBS)

securelib_LTLIBRARIES = \
	pam_unix_fprintd.la

pam_unix_fprintd_la_SOURCES = \
	bigcrypt.c \
	pam_unix_auth.c \
	support.c \
	passverify.c \
	yppasswd_xdr.c \
	md5_good.c \
	md5_broken.c \
	fprintd_bridge.c \
	pam_fprintd.c \
	marshal.c

GLIB_GENMARSHAL=`pkg-config --variable=glib_genmarshal glib-2.0`

marshal.h: fprintd-marshal.list
	$(GLIB_GENMARSHAL) --prefix=fprintd_marshal fprintd-marshal.list --header > marshal.h
marshal.c: marshal.h
	$(GLIB_GENMARSHAL) --prefix=fprintd_marshal fprintd-marshal.list --body --header > marshal.c
