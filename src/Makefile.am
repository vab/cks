bin_PROGRAMS = cksd cks_sync cks_import cks_export add search sync_manage stats delete cks_keyimg cks_reconcile

AM_CPPFLAGS = $(PKG_CPPFLAGS)

cksd_SOURCES = cksd.c cksd.h db.c db.h cgi.c cgi.h datastructures.c datastructures.h parse.c parse.h cks_parse_v4.c cks_parse_v4.h cks_parse_v3.c cks_parse_v3.h radix.c radix.h std_types.c std_types.h md5.c md5.h sha.c sha.h keys.c keys.h merge_keys.c merge_keys.h retrieve.c retrieve.h cks_config.c cks_config.h cks_socket.c cks_socket.h cks_error.c cks_error.h cks_log.c cks_log.h bithelp.h types.h cks_debug.c cks_debug.h cks_constants.h common.h
cksd_LDADD = -lpq

cks_sync_SOURCES = cks_sync.c cks_sync.h db.c db.h cks_config.c cks_config.h parse.c parse.h cks_parse_v4.c cks_parse_v4.h cks_parse_v3.c cks_parse_v3.h radix.c radix.h cgi.c cgi.h md5.c md5.h sha.c sha.h keys.c keys.h datastructures.c datastructures.h retrieve.c retrieve.h std_types.c std_types.h cks_socket.c cks_socket.h bithelp.h types.h merge_keys.c cks_error.c cks_error.h cks_debug.c cks_debug.h cks_constants.h common.h
cks_sync_LDADD = -lpq

cks_import_SOURCES = cks_import.c cks_import.h cks_config.c cks_config.h datastructures.c datastructures.h cgi.c cgi.h merge_keys.c merge_keys.h radix.c radix.h parse.c parse.h cks_parse_v4.c cks_parse_v4.h cks_parse_v3.c cks_parse_v3.h std_types.c std_types.h sha.c sha.h md5.c md5.h retrieve.c retrieve.h db.c db.h types.h bithelp.h keys.c keys.h cks_error.c cks_error.h cks_debug.c cks_debug.h cks_constants.h common.h
cks_import_LDADD = -lpq

cks_export_SOURCES = cks_export.c cks_export.h cks_config.h cks_config.c datastructures.c datastructures.h cks_debug.h cks_debug.c parse.c parse.h cks_parse_v4.c cks_parse_v4.h cks_parse_v3.c cks_parse_v3.h radix.c radix.h std_types.c std_types.h md5.c md5.h sha.c sha.h keys.c keys.h retrieve.c retrieve.h bithelp.h types.h db.h db.c merge_keys.c merge_keys.h cgi.c cgi.h cks_error.c cks_error.h cks_constants.h common.h
cks_export_LDADD = -lpq

delete_SOURCES = delete.c delete.h cgi.c cgi.h datastructures.c datastructures.h keys.c keys.h retrieve.c retrieve.h cks_config.c cks_config.h db.h db.c parse.h parse.c cks_parse_v4.c cks_parse_v4.h cks_parse_v3.c cks_parse_v3.h md5.h md5.c sha.h sha.c bithelp.h types.h std_types.h radix.h radix.c std_types.c merge_keys.c merge_keys.h cks_error.c cks_error.h cks_debug.c cks_debug.h cks_constants.h common.h
delete_LDADD = -lpq

add_SOURCES = add.c add.h retrieve.c retrieve.h radix.c radix.h std_types.c std_types.h db.c db.h cgi.c cgi.h sha.c sha.h md5.c md5.h bithelp.h merge_keys.c merge_keys.h datastructures.c datastructures.h parse.c parse.h cks_parse_v4.c cks_parse_v4.h cks_parse_v3.c cks_parse_v3.h keys.c keys.h cks_config.c cks_config.h types.h cks_error.c cks_error.h cks_debug.c cks_debug.h cks_constants.h common.h
add_LDADD = -lpq

search_SOURCES = search.c search.h radix.c radix.h db.c db.h cgi.c cgi.h sha.c sha.h retrieve.c retrieve.h md5.c md5.h parse.c parse.h cks_parse_v4.c cks_parse_v4.h cks_parse_v3.c cks_parse_v3.h datastructures.c datastructures.h keys.c keys.h std_types.c std_types.h cks_config.c cks_config.h bithelp.h types.h merge_keys.c merge_keys.h cks_error.c cks_error.h cks_debug.c cks_debug.h cks_constants.h common.h
search_LDADD = -lpq

sync_manage_SOURCES = sync_manage.c sync_manage.h cks_config.c cks_config.h cgi.c cgi.h datastructures.c datastructures.h db.c cks_constants.h cks_error.c cks_error.h common.h
sync_manage_LDADD = -lpq

stats_SOURCES = stats.c stats.h cks_config.c cks_config.h cgi.c cgi.h common.h db.c db.h datastructures.c datastructures.h cks_error.c cks_error.h
stats_LDADD = -lpq

cks_keyimg_SOURCES = cks_keyimg.c cks_keyimg.h cks_config.c cks_config.h common.h radix.c radix.h db.c db.h cgi.c cgi.h datastructures.h datastructures.c keys.c keys.h std_types.h std_types.c types.h merge_keys.c merge_keys.h cks_debug.h cks_debug.c search.h retrieve.h retrieve.c parse.c parse.h cks_parse_v4.c cks_parse_v4.h cks_parse_v3.c cks_parse_v3.h sha.c sha.h md5.h md5.c cks_error.c cks_error.h bithelp.h
cks_keyimg_LDADD = -lpq

cks_reconcile_SOURCES = cks_reconcile.c cks_reconcile.h common.h cks_constants.h datastructures.h datastructures.c cks_config.h cks_config.c cks_socket.c cks_socket.h cks_log.h cks_log.c db.h db.c cks_error.c cks_error.h
cks_reconcile_LDADD = -lpq

