/* delete.c - CKS Key Deletion Application main source file
 * Copyright (C) 2001-2011 CryptNET, V. Alex Brennen (VAB)
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

#include "delete.h"


int main(void)
{
	struct  cks_config *config = NULL;

	PGconn          *conn = NULL;

	char *method = NULL;
	char *content = NULL;
	unsigned long content_length = 0;
	char *value_0 = NULL;
	char *value_1 = NULL;
	char *val = NULL;
	char *value = NULL;

	char stmt[300];
	int result = 0;
	int rslt = 0;


	method = getenv("REQUEST_METHOD");
	if(method == NULL)
	{
		do_error_page(_("Request Method was Null.\n<P><P>Exiting..."));

		return -1;
	}
	else if(strcmp(method,"GET") == 0)
	{
		do_error_page(_("This program should be called with the POST method."));

		return -1;
	}
	else if(strcmp(method,"POST") == 0)
	{
		content_length = atoi(getenv("CONTENT_LENGTH"));

		if(content_length > 300)
		{
			do_error_page(_("Content Length expectation exceeded\n"));

			return -1;
		}
		content = (char *)malloc(content_length+1);
		if(content == NULL)
		{
			do_error_page(_("Server was unable to malloc memory.  Server out of memory."));

			return -1;
		}
		fread(content,1,content_length,stdin);
		/* TODO: check fread result */
	}
	else
	{
		do_error_page(_("Unknown Method."));

		return -1;
	}

	hex_to_ascii(content);
	/* TODO: Check for SQL injection */
	/* TODO: Free malloc'd "content" before returns */
	value_0 = strtok(content,"&");
	if(value_0 == NULL)
		return -1;
	value_1 = strtok('\0',"\0");
	if(value_1 == NULL)
		return -1;

	strtok(value_0,"=");
	value = strtok('\0',"\0");
	if(value == NULL)
		return -1;

	strtok(value_1,"=");
	val = strtok('\0',"\0");
	if(val == NULL)
		return -1;

	if( (strlen(value) != 32) && (strlen(value) != 40) &&
		(strlen(value) != 48) && (strlen(value) != 50)  )
	{
		print_admin_header(_("Error:  Invalid Fingerprint"));
		printf(_("The Fingerprint that you provided (%s) is invalid.\n"),value);
		print_admin_footer();

		return -1;
	}

	config = (struct cks_config *)malloc(sizeof(struct cks_config));
	if(config == NULL)
	{
		fprintf(stderr,"delete: malloc call failed.\n");
		if(content != NULL)
			free(content);

		return -1;
	}
	rslt = init_config(&config,0);
	if(rslt == -1)
	{
		fprintf(stderr,_("delete:  Non-Fatal Error: Failed to read config.\n"));
		fprintf(stderr,_("delete:  Using default configuration information.\n"));
	}

	conn = db_connect(config);
	if(conn == NULL)
	{
		fprintf(stderr,"Failed to connect to the Database.\n");
		print_admin_footer();
		if(content != NULL)
			free(content);
		if(config != NULL)
			free(config);

		return -1;
	}

	remove_spaces(value);

	if(!key_exists(conn,value))
	{
		print_admin_header(_("Error:  Key Not Found In DB"));
		printf(_("The key with the fingerprint '%s' was not found in the database\n"),value);
		printf(_("and therefor could not be deleted.\n"));
		print_admin_footer();
		if(content != NULL)
			free(content);
		if(config != NULL)
			free(config);

		return -1;
	}

	if(key_rejected(conn,value))
	{
		print_admin_header(_("Error:  This key has already been deleted.\n"));
		printf(_("The key with the fingerprint '%s' has already been deleted and added to the\n"),value);
		printf(_("list of rejected keys.\n"));
		print_admin_footer();
		if(content != NULL)
			free(content);
		if(config != NULL)
			free(config);

		return -1;
	}

	if(db_begin_transaction(conn) == -1)
	{
		fprintf(stderr,"Failed to start db transaction.\n");
		db_disconnect(conn);
		if(content != NULL)
			free(content);
		if(config != NULL)
			free(config);

		return -1;
	}

	rslt = delete_key_from_db(conn,value,0);
	if(rslt == -1)
	{
		print_admin_header(_("Error."));
		printf(_("Failed to delete key.\n"));
		print_admin_footer();
		if(content != NULL)
			free(content);
		if(config != NULL)
			free(config);

		return -1;
	}

	memset(stmt,0x00,300);
	if(memcmp(val,"YES",3) == 0)
	{
		snprintf(stmt,200,"insert into cks_rejected_keys values('%s')", value);
		result = db_stmt(conn,stmt,config);
		if(result == -1)
		{
			do_error_page(_("Error inserting fp into cks_rejected_keys."));
			if(content != NULL)
				free(content);
			if(config != NULL)
				free(config);

			return -1;
		}

		if(db_commit_transaction(conn) == -1)
		{
			do_error_page("Failed To commit transaction.\n");
			if(content != NULL)
				free(content);
			if(config != NULL)
				free(config);

			return -1;
		}

		print_admin_header(_("Key Deleted"));
		printf(_("The key %s has been deleted from the database and inserted into the\n"), value);
		printf(_("cks_rejected_keys table.  Attempts to add this key back into the database\n"));
		printf(_("will fail.  If you would like to add this key again, you must delete that\n"));
		printf(_("record from the cks_rejected_keys table.\n"));
		print_admin_footer();
	}
	else
	{
		if(db_commit_transaction(conn) == -1)
		{
			do_error_page("Failed To commit transaction.\n");
			if(content != NULL)
				free(content);
			if(config != NULL)
				free(config);

			return -1;
		}

		print_admin_header(_("Key Deleted"));
		printf(_("The key %s has been deleted from the database.\n"), value);
		print_admin_footer();
	}

	if(content != NULL)
	{
		free(content);
	}
	if(config != NULL)
	{
		free(config);
	}


	return 0;
}
