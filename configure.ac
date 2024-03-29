#                 -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

dnl
dnl  project setting
dnl
AC_PREREQ([2.69])
AC_INIT([cefore], [0.10.0g], [])
AC_CONFIG_AUX_DIR(autotools)
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
# limit the output message
AM_SILENT_RULES([yes])
AM_INIT_AUTOMAKE([foreign])

# Checks for programs.
cflags_save="$CFLAGS"
CFLAGS="$cflags_save"
test -n "$CFLAGS" || CFLAGS=""
AC_PROG_CC
AM_PROG_CC_C_O
LT_INIT([dlopen])
# AC_PROG_RANLIB

# Checks for typedefs, structures, and compiler characteristics.
#AC_TYPE_INT64_T
#AC_TYPE_MODE_T
#AC_TYPE_PID_T
#AC_TYPE_SIZE_T
#AC_TYPE_UINT16_T
#AC_TYPE_UINT32_T
#AC_TYPE_UINT64_T
#AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
#AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
#AC_CHECK_FUNCS([clock_gettime gethostbyaddr gettimeofday inet_ntoa memset mkdir rmdir socket strcasecmp strchr strerror strstr strtol strtoull])

# Checks OS
dnl
dnl  check OS
dnl
AM_CONDITIONAL([LINUX], [test x"$(uname -s)" = xLinux])

# Checks CEFORE_DIR
dnl
dnl  check environment variable CEFORE_DIR
dnl
if test -z "$CEFORE_DIR"; then
  CEFORE_DIR_PATH=/usr/local/
else
  CEFORE_DIR_PATH=${CEFORE_DIR}/
fi
AC_SUBST(CEFORE_DIR_PATH)

echo "#define CEFORE_VERSION \"Cefore version $VERSION\"" > src/cefnetd/version.h

# Checks for header files(OpenSSL).
dnl
dnl  check OpenSSL library
dnl
AC_ARG_WITH([openssl-dir],
  [AS_HELP_STRING([--with-openssl-dir=DIR],[An openssl path (default /usr)
  ])],
  [openssl_path=$withval],
  [openssl_path=/usr]
)
check_openssl_header=${openssl_path}/include/openssl/sha.h

AC_CHECK_FILES([${check_openssl_header}],[],[AC_MSG_ERROR("OpenSSL is not installed.")])
# CFLAGS="${CFLAGS} -I${openssl_path}/include"
CFLAGS="${CFLAGS} -DOPENSSL_API_COMPAT=0x10101000L -I${openssl_path}/include"
LDFLAGS="${LDFLAGS} -L${openssl_path}/lib64"

# checks for args

dnl
dnl  check openssl-static-link build
dnl
AC_ARG_WITH([openssl-static],
  [AS_HELP_STRING([--with-openssl-static],[openssl library static link (default no)
  ])],
  [openssl_static=yes],
  [openssl_static=no]
)
AM_CONDITIONAL(OPENSSL_STATIC, test x"${openssl_static}" = xyes)

dnl
dnl  check debug build
dnl
AC_ARG_ENABLE(
  debug,
  AS_HELP_STRING([--enable-debug], [debug build (default no)]),
  [enable_debug=yes],
  [enable_debug=no]
)
AM_CONDITIONAL(CEFDBG_ENABLE, test x"${enable_debug}" = xyes)

dnl
dnl  check csmgr
dnl
AC_ARG_ENABLE(
  csmgr,
  AS_HELP_STRING([--enable-csmgr], [content store manager (default no)]),
  [enable_csmgr=yes],
  [enable_csmgr=no]
)
AM_CONDITIONAL(CSMGR_ENABLE, test x"${enable_csmgr}" = xyes)

dnl
dnl  check samptp
dnl
AC_ARG_ENABLE(
  samptp,
  AS_HELP_STRING([--enable-samptp], [sample transport (default no)]),
  [enable_samptp=yes],
  [enable_samptp=no]
)
AM_CONDITIONAL(SAMPTP_ENABLE, test x"${enable_samptp}" = xyes)

dnl
dnl  check cache
dnl
AC_ARG_ENABLE(
  cache,
  AS_HELP_STRING([--enable-cache], [local cache on cefnetd (default no)]),
  [enable_cache=yes],
  [enable_cache=no]
)
AM_CONDITIONAL(CACHE_ENABLE, test x"${enable_cache}" = xyes)

dnl
dnl  check conpubd and tools
dnl
AC_ARG_ENABLE(
  conpub,
  AS_HELP_STRING([--enable-conpub], [conpub (default no)]),
  [enable_conpub=yes],
  [enable_conpub=no]
)
AM_CONDITIONAL(CONPUB_ENABLE, test x"${enable_conpub}" = xyes)


AC_CONFIG_FILES([
  Makefile
  src/Makefile
  src/cefnetd/Makefile
  src/include/Makefile
  src/include/cefore/Makefile
  src/lib/Makefile
  src/plugin/Makefile
  src/dlplugin/Makefile
  src/dlplugin/fwd_strategy/Makefile
  utils/Makefile
  config/Makefile
  tools/Makefile
  tools/cefgetstream/Makefile
  tools/cefputstream/Makefile
  tools/cefgetfile/Makefile
  tools/cefputfile/Makefile
  tools/cefgetfile_sec/Makefile
  tools/cefputfile_sec/Makefile
  tools/cefgetchunk/Makefile
  tools/cefgetcontent/Makefile
  tools/ccninfo/Makefile
])

dnl
dnl  check csmgr
dnl
AM_COND_IF(
  [CSMGR_ENABLE],
  [AC_CONFIG_FILES([
      tools/csmgr/Makefile
      src/csmgrd/Makefile
      src/csmgrd/csmgrd/Makefile
      src/csmgrd/plugin/Makefile
      src/csmgrd/plugin/lib/Makefile
      src/csmgrd/plugin/lib/lru/Makefile
      src/csmgrd/plugin/lib/lfu/Makefile
      src/csmgrd/plugin/lib/fifo/Makefile
      src/csmgrd/lib/Makefile
      src/csmgrd/include/Makefile
      src/csmgrd/include/csmgrd/Makefile
      tools/cefput_verify/Makefile
  ])
])

dnl
dnl  check cache
dnl
AM_COND_IF(
  [CACHE_ENABLE],
  [AC_CONFIG_FILES([
  ])
])

dnl
dnl  check conpubd and tools
dnl
AM_COND_IF(
  [CONPUB_ENABLE],
  [AC_CONFIG_FILES([
      src/conpubd/Makefile
      src/conpubd/conpubd/Makefile
      src/conpubd/plugin/Makefile
      src/conpubd/lib/Makefile
      src/conpubd/include/Makefile
      src/conpubd/include/conpubd/Makefile
      tools/conpub/Makefile
  ])
])


AC_OUTPUT
