securelibdir = $(SECUREDIR)

securelib_LTLIBRARIES = \
	pam_unix_fprintd.la

pam_unix_fprintd_la_CFLAGS = \
	$(GLIB_CFLAGS) \
	-DCHKPWD_HELPER=\"$(sbindir)/unix_chkpwd\" \
	-D"UNUSED"=

if HAVE_LIBSELINUX
	pam_unix_fprintd_la_CFLAGS += \
		-DWITH_SELINUX
endif

pam_unix_fprintd_la_LDFLAGS = \
	-no-undefined \
	-avoid-version \
	-module

pam_unix_fprintd_la_LIBADD = \
	-lpam \
	-lpthread \
	$(LIBCRYPT) \
	$(LIBSELINUX) \
	$(GLIB_LIBS)

pam_unix_fprintd_la_SOURCES = \
	bigcrypt.h \
	bigcrypt.c \
	fprintd-bridge.h \
	fprintd-bridge.c \
	fprintd-marshal.h \
	fprintd-marshal.c \
	md5.h \
	md5_broken.c \
	md5_good.c \
	pam_fprintd.h \
	pam_fprintd.c \
	pam_unix_auth.c \
	passverify.h \
	passverify.c \
	support.h \
	support.c \
	yppasswd.h \
	yppasswd_xdr.c

pam_unix_auth.c: ../linux-pam/modules/pam_unix/pam_unix_auth.c pam_unix.patch
	cp $< $@
	patch -Np1 -i $(word 2,$^) || (rm $@; false)

pam_fprintd.c: ../fprintd/pam/pam_fprintd.c pam_fprintd.patch
	cp $< $@
	patch -Np1 -i $(word 2,$^) || (rm $@; false)

GLIB_GENMARSHAL=`pkg-config --variable=glib_genmarshal glib-2.0`

fprintd-marshal.h: fprintd-marshal.list
	$(GLIB_GENMARSHAL) --prefix=fprintd_marshal $< --header > $@

fprintd-marshal.c: fprintd-marshal.list fprintd-marshal.h
	$(GLIB_GENMARSHAL) --prefix=fprintd_marshal $< --body --prototypes > $@

EXTRA_DIST = \
	fprintd-marshal.list \
	md5.c \
	md5_crypt.c \
	pam_fprintd.patch \
	pam_unix.patch

CLEANFILES = \
	pam_unix_auth.c \
	pam_unix_fprintd.c \
	fprintd-marshal.h \
	fprintd-marshal.c
