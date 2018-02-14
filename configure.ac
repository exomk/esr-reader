AC_INIT([registrator], [1.0], [atanasko.mitrev@gexo.mk])
AC_CHECK_LIB([pq], [main],, AC_MSG_ERROR([no usable libpq; please install PostgreSQL development package]))
AC_CHECK_LIB([usb], [main],, AC_MSG_ERROR([no usable libusb; please install libusb development package]))
AC_CHECK_LIB([nfc], [main],, AC_MSG_ERROR([no usable libnfc; please install libnfc development package]))
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
