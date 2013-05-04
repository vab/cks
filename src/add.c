/* add.c - Keyring addition functions
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

#include "add.h"


int main(void)
{
	struct  cks_config *config = NULL;

	char    *ptr = NULL;
 	/* CGI Vars */
	char    *method = NULL;
	char    *content = NULL;
	long     content_length = 0;
	/* End CGI Vars */
	unsigned char *radix_recd = NULL;

	PGconn          *conn = NULL;

	struct openPGP_keyring	  *keyring = NULL;

	int rslt = 0;


/*#define DEBUG */
#ifdef DEBUG
	long tmp_len_val = 0;
	char *tmp1 = NULL;

	FILE *key = NULL;
#endif

	openlog("cks_add",LOG_PID|LOG_ODELAY,LOG_USER);
	textdomain("cks");

	if(NULL == (config = (struct cks_config *)malloc(sizeof(struct cks_config))))
	{
		fprintf(stderr,_("cks_add:  Non-Fatal Error"));
		fprintf(stderr,_("cks_add:  Out of Memory Error: malloc call failed."));

		return -1;
	}
	rslt = init_config(&config);
	if(rslt == -1)
	{
		fprintf(stderr,_("cks_add:  Non-Fatal Error: Failed to read config.\n"));
		fprintf(stderr,_("cks_add:  Using default configuration information.\n"));
	}

	if(NULL == (keyring = (struct openPGP_keyring *)malloc(sizeof(struct openPGP_keyring))))
	{
		return -1;
	}

#ifdef DEBUG
	content = (char *)malloc(128000);
	if(content == NULL)
	{
		fprintf(stderr,_("malloc call failed.\n"));
		free(config);
		return -1;
	}
	tmp1 = (char *)malloc(128000);
	if(content == NULL)
	{
		fprintf(stderr,_("malloc call failed.\n"));
		free(config);
		return -1;
	}
	tmp1[0] = '\0';
	content[0] = '\0';
	if( NULL == (key = fopen("key.txt","r")))
	{
		fprintf(stderr, _("key file open failure.\n"));
		return -1;
	}
	while(!feof(key))
	{
		fgets(tmp1,78,key);
		tmp_len_val = strlen(tmp1);
		if(tmp_len_val != 0) tmp1[--tmp_len_val] = '\0';
		if(feof(key)) break;
		strncat(content,tmp1,127990);
		strncat(content,"\r\n",127990);
	}
	free(tmp1);
#else

	/* CGI */
	method = getenv("REQUEST_METHOD");
	if(method == NULL)
	{
		do_error_page(_("Method is null."));
		free(config);

		return -1;
	}
	if(strcmp("POST",method) != 0)
	{
		do_error_page(_("Only Post Method Allowed.\n"));
		free(config);

		return -1;
	}
	content_length = atoi(getenv("CONTENT_LENGTH"));
	if(content_length > 127997)
	{
		do_error_page(_("Content Length expectation exceeded."));
		free(config);

		return -1;
	}
	if(content_length < 12)
	{
		do_error_page(_("Content Length expectation not met."));
		free(config);

		return -1;
	}
	content = (char *)malloc(content_length+1);
	if(content == NULL)
	{
		do_error_page(_("Server was unable to malloc memory.  Server out of memory."));
		free(config);

		return -1;
	}

	rslt = fread(content,1,content_length,stdin);
	if(rslt == 0)
	{
	    do_error_page(_("Error reading content."));
	    if(content != NULL)
	        free(content);
	    if(config != NULL)
	        free(config);
	
	    return -1;
	}
	hex_to_ascii(content);

	/* Test value for SQL injection */
	if( (strchr(content, '\'') != NULL) || (strchr(content, ';') != NULL) )
	{
		do_error_page(_("The characters ' and ; are currently not allowed in queries."));
		if(content != NULL)
		    free(content);
		if(config != NULL)
		    free(config);

		return -1;
	}
#endif
	ptr = content;

	if(NULL == (radix_recd = (char *)malloc(strlen(ptr)+1)))
	{
		do_error_page(_("Failed to malloc memory for radix_recd"));
		free(config);

		return -1;
	}
	strncpy(radix_recd,ptr,strlen(ptr));
	/* End CGI */
	init_openPGP_keyring(&keyring,128000);
	if(keyring == NULL)
	{
		do_error_page(_("Failed to malloc region for keyring!\n"));
        	printf(_("Key ring is null?\n"));
		free(config);

		return -1;
	}
	rslt = process_buffer(ptr,keyring,D_SOURCE_ADD_CGI);
	if(rslt == -1)
	{
		do_error_page(_("Failed to process buffer.\n"));
		fprintf(stderr, _("add.c:  Failed to process buffer.\n"));
		free_keyring(&keyring);
		free(config);

		return -1;
	}
	rslt = parse_keyring(&keyring,D_SOURCE_ADD_CGI);
	if(rslt == -1)
	{
		do_error_page(_("Failed to parse keyring.\n"));
		fprintf(stderr, _("add.c:  Failed to parse key ring.\n"));
		free_keyring(&keyring);
		free(config);

		return -1;
	}

	/* Make the DB Connection. */
	conn = db_connect(config);
	if(conn == NULL)
	{
		fprintf(stderr,"Failed to connect to the db.\n");
		free(config);

		return -1;
	}

	rslt = add_keyring_to_db(conn,keyring,D_SOURCE_ADD_CGI);
	if(rslt == -1)
	{
		fprintf(stderr,"add.c: add_keyring_to_db(): insert failed.\n");
	}
	db_disconnect(conn);

	/* Free Up Used Memory */
	/*  Destroy the Key Information */
	free_keyring(&keyring);

	if(radix_recd != NULL)
        	free(radix_recd);
	if(content != NULL)
        	free(content);
	if(config != NULL)
        	free(config);

	return 0;
}
