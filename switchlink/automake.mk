AM_CPPFLAGS += -I /usr/include/libnl3
AM_CPPFLAGS += -I $(top_srcdir)/switchlink/xxhash/include
AM_CPPFLAGS += -I $(top_srcdir)/switchlink/submodules/SAI/inc

AM_CFLAGS += -I /usr/include/libnl3
AM_CFLAGS += -I $(top_srcdir)/switchlink/xxhash/include
AM_CFLAGS += -I $(top_srcdir)/switchlink/submodules/SAI/inc

EXTRA_DIST += $(top_srcdir)/switchlink/submodules/SAI
EXTRA_DIST += switchsai

NETLINK_LIBS = -lnl-route-3 -lnl-3

lib_LTLIBRARIES += switchlink/libswitchlink.la

switchlink_libswitchlink_la_LDFLAGS = \
        $(OVS_LTINFO) \
        -Wl,--version-script=$(top_builddir)/switchlink/libswitchlink.sym \
        $(AM_LDFLAGS)

switchlink_libswitchlink_la_SOURCES = \
   switchlink/switchlink_address.c \
   switchlink/switchlink_db.c \
   switchlink/switchlink_db.h \
   switchlink/switchlink_db_int.h \
   switchlink/switchlink.h \
   switchlink/switchlink_int.h \
   switchlink/switchlink_link.c \
   switchlink/switchlink_link.h \
   switchlink/switchlink_main.c \
   switchlink/switchlink_neigh.c \
   switchlink/switchlink_neigh.h \
   switchlink/switchlink_route.c \
   switchlink/switchlink_route.h \
   switchlink/switchlink_sai.c \
   switchlink/switchlink_sai.h \
   switchlink/xxhash/include/xxhash.h \
   switchlink/xxhash/src/xxhash.c

switchlink_libswitchlink_la_CPPFLAGS = $(AM_CPPFLAGS)
switchlink_libswitchlink_la_CPPFLAGS += -DHAVE_NLA_BITFIELD32
switchlink_libswitchlink_la_CPPFLAGS += -I ./switchsai

switchlink_libswitchlink_la_CFLAGS = $(AM_CFLAGS)
switchlink_libswitchlink_la_CFLAGS += -DHAVE_NLA_BITFIELD32
switchlink_libswitchlink_la_CFLAGS += -I ./switchsai

switchlink_libswitchlink_la_LIBADD = $(NETLINK_LIBS)
switchlink_libswitchlink_la_LIBADD += switchsai/libswitchsai.la

pkgconfig_DATA += \
    switchlink/libswitchlink.pc

CLEANFILES += switchlink/libswitchlink.sym
CLEANFILES += switchlink/libswitchlink.pc
