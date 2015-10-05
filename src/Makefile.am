AUTOMAKE_OPTIONS = -Wno-override
include_HEADERS = repsheet.h
lib_LTLIBRARIES = librepsheet.la
librepsheet_la_SOURCES = librepsheet.c \
                         common.c      \
                         cidr.c        \
                         blacklist.c   \
                         whitelist.c   \
                         marked.c      \
                         xff.c         \
                         vector.c      \
                         check_cidr.c
librepsheet_la_LDFLAGS = -lm -lhiredis -version-info 7:0:1
librepsheet_la_CFLAGS = -std=c99

