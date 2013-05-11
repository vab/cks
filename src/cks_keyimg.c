/* cks_keyimg.c - Code to display image packets in pgp keys
 * Copyright (C) 2001-2004 CryptNET, V. Alex Brennen (VAB)
 *
 * This file is part of the CryptNET OpenPGP Public Key Server (cks).
 *
 * cks is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * cks is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */
#include "cks_keyimg.h"


struct openPGP_pubkey *key_result = NULL;

int	main(void)
{
	struct  cks_config *config = NULL;

	PGconn          *conn = NULL;

	char *method = NULL;
	char *content = NULL;
	unsigned int content_length = 0;
	char *name = NULL;
	char *val = NULL;
	char *value = NULL;
	unsigned char *fingerprint = NULL;

	int rslt = 0;
	int tmp_var = 0;


	config = (struct cks_config *)malloc(sizeof(struct cks_config));
	if(config == NULL)
	{
		fprintf(stderr, "Failed to malloc config\n");

		return -1;
	}
	rslt = init_config(&config);
	if(rslt == -1)
	{
		fprintf(stderr,_("cks: cks_keyimg.c:  Non-Fatal Error: Failed to read config.\n"));
		fprintf(stderr,_("cks: cks_keyimg.c:  Using default configuration information.\n"));
	}

	conn = db_connect(config);
	if(conn == NULL)
	{
		do_error_page(_("Failed to connect to postgres database."));
		fprintf(stderr,_("cks: cks_keyimg.c:  Connection to database failed.\n"));
		fprintf(stderr,"cks: cks_keyimg.c:  %s", PQerrorMessage(conn));
		db_disconnect(conn);
		if(config != NULL)
			free(config);

		return -1;
	}

	#ifdef DEBUG
	fingerprint = (char *)malloc(100);
	strcpy(fingerprint,"72F871AD580481D14C84CADC08B779A592987FBD");
	#else
	method = getenv("REQUEST_METHOD");
	if(method == NULL)
	{
		fprintf(stderr,"Method was null.\n");
		db_disconnect(conn);
		if(config != NULL)
			free(config);

		return 0;
	}
	if(method == NULL)
	{
		fprintf(stderr, _("search.c:  Request Method is Null.\nExiting...\n"));
		db_disconnect(conn);
		if(config != NULL)
			free(config);

		return -1;
	}
	if(strcmp(method,"GET") == 0)
	{
		content_length = strlen(getenv("QUERY_STRING"));
		if(content_length > 300)
		{
			do_error_page(_("Content Length expectation exceeded\n"));
			db_disconnect(conn);
			if(config != NULL)
				free(config);

			return -1;
		}
		/* TODO: Make sure content length is not too small */
		content = (char *)malloc(content_length+1);
		if(content == NULL)
		{
			do_error_page(_("Server was unable to malloc memory.  Server out of memory."));
			db_disconnect(conn);
			if(config != NULL)
				free(config);

			return -1;
		}
		strncpy(content,getenv("QUERY_STRING"),content_length);
	}

	hex_to_ascii(content);
	value = (unsigned char *)malloc(content_length+1);
	if(value == NULL)
	{
		do_error_page("cks_keyimg.c: Malloc call failed. Out of Memory.\n");
		db_disconnect(conn);
		if(config != NULL)
			free(config);

		return -1;
	}
	fingerprint = (unsigned char *)malloc(content_length+1);
	if(fingerprint == NULL)
	{
		do_error_page("cks_keyimg.c: Malloc call failed. Out of Memory.\n");
		db_disconnect(conn);
		if(config != NULL)
			free(config);

		return -1;
	}
	strncpy(value,content,41);
	strncpy(fingerprint,content,41);
	if(!(value))
	{
		do_error_page(_("Error: NULL Search value. Please, hit the back button on your browser and search again."));
		if(value != NULL)
		{
			free(value);
		}
		if(fingerprint != NULL)
		{
			free(fingerprint);
		}
		db_disconnect(conn);
		if(config != NULL)
			free(config);

		return 0;
	}

	/* TODO: Move this up higher so we don't have to do the allocs if there's bad code */
	/* Test value for SQL injection */
	if( (strchr(value, '\'') != NULL) || (strchr(value, ';') != NULL) )
	{
		do_error_page(_("The characters ' and ; are currently not allowed in queries."));
		if(value != NULL)
		{
			free(value);
		}
		if(fingerprint != NULL)
		{
			free(fingerprint);
		}
		db_disconnect(conn);
		if(config != NULL)
			free(config);

		return 0;
	}
	#endif

	/* Search by Fingerprint */
	remove_spaces(fingerprint);
	if(((strlen(fingerprint)) != 32) && ((strlen(fingerprint)) != 40))
	{
		do_error_page(_("The characters ' and ; are currently not allowed in queries."));
		if(value != NULL)
		{
			free(value);
		}
		if(fingerprint != NULL)
		{
			free(fingerprint);
		}
		db_disconnect(conn);
		if(config != NULL)
			free(config);

		return -1;
	}

	retrieve_key_and_display(conn,fingerprint,1,config);

	if(value != NULL)
	{
		free(value);
	}
	if(fingerprint != NULL)
	{
		free(fingerprint);
	}
	db_disconnect(conn);
	if(config != NULL)
	{
		free(config);
	}

	return 0;
}

int  retrieve_key_and_display(PGconn *conn, char *fingerprint, unsigned int full,struct cks_config *config)
{
	unsigned long i = 0;
	FILE *test = NULL;
	struct openPGP_packet *walk_packet = NULL;

	int rslt = 0;


	key_result = (struct openPGP_pubkey *)retrieve_pubkey(conn,fingerprint,D_SOURCE_ADD_CGI);
	if(key_result == NULL)
	{
		fprintf(stderr,_("Failed to retrieve key: %s\n"),fingerprint);
		do_error_page(_("Failed to retrieve key from database.\n"));

		return -1;
	}

	rslt = parse_pubkey(&key_result,D_SOURCE_SEARCH_CGI);
	if(rslt == -1)
	{
		fprintf(stderr,_("cks: cks_keyimg.c: Failed to parse retrieved pubkey: %s\n"),fingerprint);

		return -1;
	}
	rslt = parse_packets(&key_result,D_SOURCE_SEARCH_CGI);
	if(rslt == -1)
	{
		fprintf(stderr,_("Failed to parse retrieved pubkey's packets: %s\n"),fingerprint);

		return -1;
	}

//	dump_pubkey_packet_info_stderr(key_result);
	if(NULL == (test = fopen("/tmp/test.jpg","w")))
	{
		fprintf(stderr,"Failed to open out put file.\n");

		return -1;
	}

	fprintf(stderr,"image_len = %lu\n",key_result->image_len);
	fputc(0xd8,test);
	fputc(0xff,test);
	fputc(0xe0,test);
	fputc(0xff,test);
	fputc(0x10,test);
	fputc(0x00,test);
	fputc(0x46,test);
	fputc(0x4a,test);
	fputc(0x46,test);
	fputc(0x49,test);
	fputc(0x01,test);
	fputc(0x00,test);
	for(i=0;i<key_result->image_len;i++)
	{
		fputc(key_result->img_data[i],test);
	}

	fclose(test);
	printf("Content-type: image/jpg\n\n");
	printf("%c%c%c%c%c%c%c%c%c%c\n", 0xd8, 0xff, 0xe0, 0xff, 0x10, 0x00, 0x46, 0x4a, 0x46, 0x49, 0x01, 0x00);
	for(i=0;i<key_result->image_len;i++)
	{
		printf("%c",key_result->img_data[i]);
	}

	free_pubkey(&key_result);

	return rslt;
}
