AM_CPPFLAGS += -I $(top_srcdir)/switchlink/submodules/SAI/inc
AM_CFLAGS += -I $(top_srcdir)/switchlink/submodules/SAI/inc

EXTRA_DIST += $(top_srcdir)/switchlink/submodules/SAI
EXTRA_DIST += switchapi/linux_networking/headers.p4
EXTRA_DIST += switchapi/linux_networking/linux_networking.p4
EXTRA_DIST += switchapi/linux_networking/metadata.p4
EXTRA_DIST += switchapi/linux_networking/parser.p4
EXTRA_DIST += switchapi/linux_networking/routing.p4
EXTRA_DIST += switchapi/linux_networking/tunnel.p4

lib_LTLIBRARIES += switchapi/libswitchapi.la

switchapi_libswitchapi_la_LDFLAGS = \
        $(OVS_LTINFO) \
        -Wl,--version-script=$(top_builddir)/switchapi/libswitchapi.sym \
        $(AM_LDFLAGS)

switchapi_libswitchapi_la_SOURCES = \
    switchapi/switch_base_types.h \
    switchapi/switch_internal.h \
    switchapi/switch_interface.h \
    switchapi/switch_types_int.h \
    switchapi/switch_port_int.h \
    switchapi/switch_status.h \
    switchapi/switch_id.h \
    switchapi/switch_id.c \
    switchapi/switch_table.h \
    switchapi/switch_table.c \
    switchapi/switch_config_int.h \
    switchapi/switch_config.h \
    switchapi/switch_config.c \
    switchapi/switch_device_int.h \
    switchapi/switch_device.h \
    switchapi/switch_device.c \
    switchapi/switch_handle_int.h \
    switchapi/switch_handle.h \
    switchapi/switch_handle.c \
    switchapi/switch_utils.c \
    switchapi/switch_port.h \
    switchapi/switch_port.c \
    switchapi/switch_pd_port.c \
    switchapi/switch_tunnel_int.h \
    switchapi/switch_tunnel.h \
    switchapi/switch_tunnel.c \
    switchapi/switch_pd_tunnel.c \
    switchapi/switch_rif.c \
    switchapi/switch_rif.h \
    switchapi/switch_rif_int.h \
    switchapi/switch_rmac.c \
    switchapi/switch_rmac_int.h \
    switchapi/switch_rmac.h \
    switchapi/switch_neighbor.c \
    switchapi/switch_neighbor.h \
    switchapi/switch_neighbor_int.h \
    switchapi/switch_nhop.c \
    switchapi/switch_nhop_int.h \
    switchapi/switch_nhop.h \
    switchapi/switch_pd_routing.c \
    switchapi/switch_pd_routing.h \
    switchapi/switch_fdb.h \
    switchapi/switch_fdb.c \
    switchapi/switch_pd_fdb.c \
    switchapi/switch_l3.c \
    switchapi/switch_l3.h \
    switchapi/switch_l3_int.h \
    switchapi/switch_vrf.c \
    switchapi/switch_vrf.h \
    switchapi/switch_pd_utils.c \
    switchapi/switch_pd_utils.h \
    switchapi/switch_pd_p4_name_mapping.h


switchapi_libswitchapi_la_CPPFLAGS = $(AM_CPPFLAGS)
switchapi_libswitchapi_la_CFLAGS = $(AM_CFLAGS)

pkgconfig_DATA += \
    switchapi/libswitchapi.pc

CLEANFILES += switchapi/libswitchapi.sym
CLEANFILES += switchapi/libswitchapi.pc
