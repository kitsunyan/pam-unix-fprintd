AC_INIT([pam-unix-fprintd],[0.9.0])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign -Wall -Wno-portability])
AC_PREREQ([2.61])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_HOST

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_SUBST(PACKAGE)
AC_SUBST(VERSION)

AC_PREFIX_DEFAULT(/usr)

test "${prefix}" = "NONE" && prefix="/usr"
if test ${prefix} = '/usr'
then
	if test ${sysconfdir} = '${prefix}/etc'
	then
		sysconfdir="/etc"
	fi
	if test ${libdir} = '${exec_prefix}/lib'
	then
		case "$host_cpu" in
			x86_64|ppc64|s390x|sparc64)
				libdir="/lib64" ;;
			*)
				libdir="/lib" ;;
		esac
	fi
	if test ${sbindir} = '${exec_prefix}/sbin'
	then
		sbindir="/sbin"
	fi
fi

AC_USE_SYSTEM_EXTENSIONS

LT_INIT([disable-static])
AC_ENABLE_STATIC([no])
AC_ENABLE_SHARED([yes])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_CC_C_O

AC_ARG_ENABLE(securedir,
	AS_HELP_STRING([--enable-securedir=DIR],[path to location of PAMs @<:@default=$libdir/security@:>@]),
	SECUREDIR=$enableval, SECUREDIR=$libdir/security)
AC_SUBST(SECUREDIR)

AC_CHECK_HEADERS(xcrypt.h crypt.h)
AS_IF([test "x$ac_cv_header_xcrypt_h" = "xyes"],
	[crypt_libs="xcrypt crypt"],
	[crypt_libs="crypt"])

BACKUP_LIBS=$LIBS
AC_SEARCH_LIBS([crypt],[$crypt_libs], LIBCRYPT="${ac_lib:+-l$ac_lib}", LIBCRYPT="")
AC_CHECK_FUNCS(crypt_r crypt_gensalt_r)
LIBS=$BACKUP_LIBS
AC_SUBST(LIBCRYPT)
if test "$LIBCRYPT" = "-lxcrypt" -a "$ac_cv_header_xcrypt_h" = "yes" ; then
	AC_DEFINE([HAVE_LIBXCRYPT], 1, [Define to 1 if xcrypt support should be compiled in.])
fi

AC_ARG_ENABLE([selinux],
	AS_HELP_STRING([--disable-selinux],[do not use SELinux]),
	WITH_SELINUX=$enableval, WITH_SELINUX=yes)
if test "$WITH_SELINUX" == "yes" ; then
	AC_CHECK_LIB([selinux],[getfilecon], LIBSELINUX="-lselinux", LIBSELINUX="")
else
	LIBSELINUX=""
fi
AC_SUBST(LIBSELINUX)
AM_CONDITIONAL([HAVE_LIBSELINUX], [test ! -z "$LIBSELINUX"])
if test ! -z "$LIBSELINUX" ; then
	AC_DEFINE([WITH_SELINUX], 1, [Defined if SE Linux support is compiled in])
	BACKUP_LIBS=$LIBS
	LIBS="$LIBS $LIBSELINUX"
	AC_CHECK_FUNCS(setkeycreatecon)
	AC_CHECK_FUNCS(getseuser)
	LIBS=$BACKUP_LIBS
fi

PKG_CHECK_MODULES(GLIB, glib-2.0 dbus-glib-1)
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(fcntl.h limits.h malloc.h sys/file.h sys/ioctl.h sys/time.h syslog.h net/if.h termio.h unistd.h sys/fsuid.h inittypes.h)

AC_C_BIGENDIAN
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

dnl Checks for library functions.
AC_TYPE_GETGROUPS
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MEMCMP
AC_FUNC_VPRINTF
AC_CHECK_FUNCS(fseeko getdomainname gethostname gettimeofday lckpwdf mkdir select)
AC_CHECK_FUNCS(strcspn strdup strspn strstr strtol uname)
AC_CHECK_FUNCS(getutent_r getpwnam_r getpwuid_r getgrnam_r getgrgid_r getspnam_r)
AC_CHECK_FUNCS(getgrouplist getline getdelim)
AC_CHECK_FUNCS(inet_ntop inet_pton innetgr ruserok_af)

AC_CHECK_FUNCS(unshare, [UNSHARE=yes], [UNSHARE=no])
AM_CONDITIONAL([HAVE_UNSHARE], [test "$UNSHARE" = yes])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
