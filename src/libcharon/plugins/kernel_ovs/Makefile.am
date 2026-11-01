AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-kernel-ovs.la
else
plugin_LTLIBRARIES = libstrongswan-kernel-ovs.la
endif

libstrongswan_kernel_ovs_la_SOURCES = \
	kernel_ovs_plugin.h kernel_ovs_plugin.c \
	kernel_ovs_ipsec.h kernel_ovs_ipsec.c \
	ovs_ctl.h ovs_ctl.c

libstrongswan_kernel_ovs_la_LDFLAGS = -module -avoid-version

EXTRA_DIST = README.md
