dnl Process this file with autoconf to produce a configure script.
AC_INIT([cks], [0.2.4])
AC_CONFIG_SRCDIR([src/cksd.c])
AM_INIT_AUTOMAKE

dnl Set of available languages.
ALL_LINGUAS="de es"

dnl Checks for programs.
AC_PROG_CC

dnl Checks for libraries.
if test $PG_LIB_DIR; then
PKG_LIBS="${PKG_LIBS} -lpq"
#   PKG_LDFLAGS="-L${PG_LIB_DIR}"
PKG_LIBS="-L${PG_LIB_DIR} ${PKG_LIBS}"
else
AC_CHECK_LIB(pq, main, FOUND_LIBPQ=1)
if test $FOUND_LIBPQ; then
PKG_LIBS="$PKG_LIBS -lpq"
else
echo
echo I could not find your libpq.  Either it is missing
echo or is installed in a non-standard location.  If libpq
echo is installed, set PG_LIB_DIR to the directory containing
echo libpq and reinstall the RPgSQL package.  PG_LIB_DIR
echo only needs to be set during package installation,
echo not while running RPgSQL.
echo
exit 1
fi
fi

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(limits.h unistd.h)

dnl Checks for postgres header files.
AC_CHECK_HEADERS([postgresql/libpq-fe.h libpq-fe.h ${PG_INCLUDE_DIR}/libpq-fe.h], [break], [AC_MSG_ERROR([PostgreSQL headers not found or not usable])])
PKG_CPPFLAGS="-I/usr/include/postgresql"

if test $PG_INCLUDE_DIR; then
PKG_CPPFLAGS="-I${PG_INCLUDE_DIR}"
fi

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_STRUCT_TM

dnl gettextize told me to
dnl AM_GNU_GETTEXT([external])

dnl Checks for library functions.
AC_FUNC_MEMCMP
AC_CHECK_FUNCS(socket strstr)

dnl check for tcpwrapper
AC_ARG_WITH(libwrap, AC_HELP_STRING([--with-libwrap],
				[Link with the TCP Wrapper libwrap]),
	AC_CHECK_LIB(wrap,main))

AC_SUBST(PKG_CPPFLAGS)
AC_SUBST(PKG_LIBS)
#AC_SUBST(PKG_LDFLAGS)
AC_SUBST(PKG_CFLAGS)
AC_SUBST(PKG_FFLAGS)

# Customize DB parameters.
AC_SUBST(DBWWWUSER, "httpd")
AC_ARG_WITH(db-www-user,
            AC_HELP_STRING([--with-db-www-user=STR],
                           [userid that webserver run scripts under (httpd)]),
	DBWWWUSER="${withval}")
AC_MSG_NOTICE([userid webserver invoke CGI-scripts under... $DBWWWUSER])

AC_SUBST(DBKEYUSER, "keyserver")
AC_ARG_WITH(db-key-user,
            AC_HELP_STRING([--with-db-key-user=STR],
                           [userid that you will run cksd as (keyserver)]),
	DBKEYUSER="${withval}")
AC_MSG_NOTICE([userid that you will run cksd under... $DBKEYUSER])

test -z "$USER" && USER=root
AC_SUBST(DBUSER, $USER)
AC_ARG_WITH(db-user,
            AC_HELP_STRING([--with-db-user=STR],
                           [human user with full access to database]),
	DBUSER="${withval}")
AC_MSG_NOTICE([human user with full access to database... $DBUSER])

AC_SUBST(DBNAME, "pgp_keys")
AC_ARG_WITH(db-name,
            AC_HELP_STRING([--with-db-name=STR],
                           [name of database to use (pgp_keys)]),
	DBNAME="${withval}")
AC_MSG_NOTICE([name of database to use... $DBNAME])

# Where to put cks.conf.
if test [ \"NONE\" == \"$prefix\" ]; then
AC_SUBST(CONF, "/etc/cks.conf")
AC_ARG_WITH(conf,
            AC_HELP_STRING([--with-conf=FILE],
                           [where config file lives [[/etc/cks.conf]]]),
	CONF="${withval}")
else
AC_SUBST(CONF, "$prefix/etc/cks.conf")
AC_ARG_WITH(conf,
            AC_HELP_STRING([--with-conf=FILE],
                           [where config file lives [[PREFIX/etc/cks.conf]]]),
        CONF="${withval}")
fi
AC_MSG_NOTICE([where to store config... $CONF])
AC_DEFINE_UNQUOTED(CONF, "$CONF", [Where to find cks.sql.])

AC_OUTPUT([Makefile cks.sql cks.conf html/Makefile src/Makefile doc/Makefile])
