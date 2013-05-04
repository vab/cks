/* search.c - database searching functions
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

#include "search.h"


int main(void)
{
	struct  cks_config *config = NULL;

	PGconn          *conn = NULL;

	char *method = NULL;
	char *content = NULL;
	unsigned long content_length = 0;
	char *name = NULL;
	char *val = NULL;
	char *value = NULL;

	int rslt = 0;
	int tmp_var = 0;

	
	config = (struct cks_config *)malloc(sizeof(struct cks_config));
	if(config == NULL)
	{
		fprintf(stderr,_("cks_export: Fatal Error:  Malloc Call Failed: Out of memroy.\n"));

		return -1;
	}
	rslt = init_config(&config);
	if(rslt == -1)
	{
		fprintf(stderr,_("search:  Non-Fatal Error: Failed to read config.\n"));
		fprintf(stderr,_("search:  Using default configuration information.\n"));
	}

	/* Make the DB Connection. */
	conn = db_connect(config);
	if(conn == NULL)
	{
		fprintf(stderr,"Failed to connect to the db.\n");
		free(config);

		return -1;
	}

	method = getenv("REQUEST_METHOD");
	if(method == NULL)
	{
		search_by_uid(conn,"vab@cryptnet.net",config);
		/*search_by_uid(conn,"vab@cryptnet.net",config); */
		db_disconnect(conn);

		free(config);

		return 0;
	}
	if(method == NULL)
	{
		fprintf(stderr, _("search.c:  Request Method is Null.\nExiting...\n"));
		db_disconnect(conn);
		free(config);

		return -1;
	}
	else if(strcmp(method,"GET") == 0)
	{
		content_length = strlen(getenv("QUERY_STRING"));
		if(content_length > 300)
		{
			do_error_page(_("Content Length expectation exceeded\n"));
			db_disconnect(conn);
			free(config);

			return -1;
		}
		content = (char *)malloc(content_length+1);
		if(content == NULL)
		{
			do_error_page(_("Server was unable to malloc memory.  Server out of memory."));
			db_disconnect(conn);
			free(config);

			return -1;
		}
		memset(content,0x00,content_length+1);
		strncpy(content,getenv("QUERY_STRING"),content_length);
	}
	else if(strcmp(method,"POST") == 0)
	{
		content_length = atoi(getenv("CONTENT_LENGTH"));

		if(content_length > 300)
		{
			do_error_page(_("Content Length expectation exceeded\n"));
			db_disconnect(conn);
			free(config);

			return -1;
		}
		content = (char *)malloc(content_length+1);
		if(content == NULL)
		{
			do_error_page(_("Server was unable to malloc memory.  Server out of memory."));
			db_disconnect(conn);
			free(config);

			return -1;
		}
		rslt = fread(content,1,content_length,stdin);
		if(rslt == 0)
		{
		    do_error_page(_("Error reading content."));
		    db_disconnect(conn);
		    if(config != NULL)
		        free(config);
		    
		    return -1;
		}
		content[content_length] = '\0';
	}
	else
	{
		do_error_page(_("Unknown Method."));
		db_disconnect(conn);
		free(config);

		return -1;
	}

	hex_to_ascii(content);

	name = strtok(content,"&");
	if(name == NULL)
	{
		fprintf(stderr,"name was null\n");
		
		return -1;
	}
	val = strtok('\0',"\0");
	if(!(val))
	{
		do_error_page(_("Error: NULL Search value. Please, hit the back button on your browser and search again."));
		db_disconnect(conn);
		free(config);

		return 0;
	}
	strtok(val,"=");
	value = strtok('\0',"\0");
	if(!(value))
	{
		do_error_page(_("Error: NULL Search value. Please, hit the back button on your browser and search again."));
		db_disconnect(conn);
		free(config);

		return 0;
	}

	/* Test value for SQL injection */
	if( (strchr(value, '\'') != NULL) || (strchr(value, ';') != NULL) )
	{
		do_error_page(_("The characters ' and ; are currently not allowed in queries."));
		db_disconnect(conn);
		free(config);

		return 0;
	}

	print_header(_("Search Results:"));

	if(strcmp("stype=uid",name) == 0)
	{
                search_by_uid(conn,value,config);
	}
	else if(strcmp("stype=fp",name) == 0)
	{
		rslt = search_by_fingerprint(conn,value,config);
		if(rslt != 0)
		{
			fprintf(stderr,"Function search_by_fingerprint() returned and error: %d\n", rslt);

			return -1;
		}
	}
	else if(strcmp("stype=keyid_4b",name) == 0)
	{
		if(memcmp(value,"00000000",8) == 0)
		{
			print_pgp5_x509_note();
		}
		else
		{
			search_by_keyid(conn,value,config);
		}
	}
	else if(strcmp("stype=keyid_8b",name) == 0)
	{
		search_by_fkeyid(conn,value,config);
	}
	else if(strcmp("stype=keyring",name) == 0)
	{
		search_ret_keyring(conn,value,config);
	}
	else if(strcmp("stype=signers",name) == 0)
	{
		search_ret_with_signers(conn,value,config);
	}
	else
	{
		do_error_page(_("Invalid query. Search type not understood."));
		db_disconnect(conn);
		free(config);

		return 0;
	}

	print_footer();

	db_disconnect(conn);
	if(config != NULL)
		free(config);

	return 0;
}


int search_by_uid(PGconn *conn, char *uid, struct cks_config *config)
{
	char stmt[200];
	PGresult *result = NULL;
	unsigned int nts = 0;
	int rslt = 0;

	/*
		It's probably a good idea here to do some kind of test to see if this
		is an email address, then maybe query against a seperate table that is
		indexed by only email address.  That could yield a speed up.
	*/
		memset(stmt,0x00,200);
        snprintf(stmt,199,"select DISTINCT(fp) from cks_uid_table where uid~*'%s'",uid);

        result = PQexec(conn, stmt);
        if((PQresultStatus(result) != PGRES_TUPLES_OK) && (PQresultStatus(result) != PGRES_COMMAND_OK))
        {
                fprintf(stderr, _("search.c:  Command didn't return tuples properly\n"));
                fprintf(stderr, _("search.c:  Failing Query: %s\n"),stmt);
				fprintf(stderr,"search.h 255: Result = %d\n", PQresultStatus(result));
                PQclear(result);
                db_exit_nicely(conn);
        }

        nts = PQntuples(result);
        if(nts == 0)
        {
                printf(_("No Records Found.\n"));
        }
        else if(nts == 1)
        {
                rslt = retrieve_key(conn,PQgetvalue(result,0,0),1,config);
        }
        else if(nts > 1)
        {
                int i = 0;

                for(i = 0; i<nts;i++)
                {
                       rslt = retrieve_key_info(conn,PQgetvalue(result,i,0));
		       fflush(0);
		       if(i == config->max_ret) break;
                }
        }
        else
        {
                fprintf(stderr, _("search.c:  Query Failed: Weird Tuples Returned.\n"));
        }
        PQclear(result);

        return rslt;
}


int search_by_keyid(PGconn *conn, char *keyid, struct cks_config *config)
{
        char stmt[161];
        PGresult *result = NULL;
	int rslt = 0;
        unsigned int nts = 0;


	remove_spaces(keyid);
	if((memcmp(keyid,"0X",2) == 0))
	{
		keyid = &keyid[2];
	}
	if((strlen(keyid)) != 8)
	{
		return -1;
	}

        snprintf(stmt,160,"select key_id,fkey_id,fp from cks_keyid_table where key_id = '%s'", keyid);

        result = PQexec(conn, stmt);

        if((PQresultStatus(result) != PGRES_TUPLES_OK) && (PQresultStatus(result) != PGRES_COMMAND_OK))
        {
                fprintf(stderr, _("search.c:  Command didn't return tuples properly.\n"));
                fprintf(stderr, _("search.c:  Failing Query: %s\n"),stmt);
                PQclear(result);
                db_exit_nicely(conn);
        }

        nts = PQntuples(result);

	if(nts == 0)
        {
                printf(_("No Records Found.\n"));
        }
	else if(nts == 1)
	{
                rslt = retrieve_key(conn,PQgetvalue(result,0,2),1,config);
	}
	else if(nts > 1)
	{
                int i = 0;

                for(i = 0; i<nts;i++)
                {
                       rslt = retrieve_key_info(conn,PQgetvalue(result,i,2));
		       fflush(0);
		       if(i == config->key_ret) break;
                }
	}
	else
	{
		fprintf(stderr, _("search.c:  Query Failed: Weird Tuples Returned.\n"));
	}

	PQclear(result);


	return rslt;
}


int search_by_fkeyid(PGconn *conn, char *fkeyid, struct cks_config *config)
{
	char stmt[200];
	PGresult *result = NULL;
	int rslt = 0;
	unsigned int nts = 0;


	memset(stmt,0x00,200);
	remove_spaces(fkeyid);
	if((memcmp(fkeyid,"0X",2) == 0))
	{
		fkeyid = &fkeyid[2];
	}

	if((strlen(fkeyid)) != 16)
	{
		return -1;
	}

	snprintf(stmt,160,"select key_id,fkey_id,fp from cks_keyid_table where fkey_id = '%s'",fkeyid);

	result = PQexec(conn, stmt);
	if((PQresultStatus(result) != PGRES_TUPLES_OK) && (PQresultStatus(result) != PGRES_COMMAND_OK))
	{
		fprintf(stderr, _("search.c:  Command didn't return tuples properly.\n"));
		fprintf(stderr, _("search.c:  Failing Query: %s\n"),stmt);
		PQclear(result);
		db_exit_nicely(conn);
	}

	nts = PQntuples(result);
	if(nts == 0)
	{
		printf(_("No Records Found.\n"));
	}
	else if(nts == 1)
	{
		rslt = retrieve_key(conn,PQgetvalue(result,0,2),1,config);
	}
	else if(nts > 1)
	{
		int i = 0;

		for(i = 0; i<nts;i++)
		{
			rslt = retrieve_key_info(conn,PQgetvalue(result,i,2));
			fflush(0);
			if(i == config->key_ret) break;
		}
	}
	else
	{
		fprintf(stderr, _("search.c:  Query Failed: Weird Tuples Returned.\n"));
	}

	PQclear(result);


	return rslt;
}


int search_by_fingerprint(PGconn *conn, char *fingerprint,struct cks_config *config)
{
	int rslt = 0;


	remove_spaces(fingerprint);
	if(((strlen(fingerprint)) != 32) && ((strlen(fingerprint)) != 40))
	{
		return -1;
	}
	rslt = retrieve_key(conn,fingerprint,1,config);
	if(rslt != 0)
	{
		fprintf(stderr, "Function retrieve_key() return an error: %d\n",rslt);
	}


	return rslt;
}


int search_ret_keyring(PGconn *conn,char *search_term,struct cks_config *config)
{
	int rslt = 0;

	/* Here we're only going to search by text regex */


	return rslt;
}


int search_ret_with_signers(PGconn *conn,char *search_term,struct cks_config *config)
{
	int rslt = 0;

	if( (strlen(search_term) == 32) || (strlen(search_term) == 40) )
	{
		/* Search by Fingerprint */

	}
	else if( (strlen(search_term) == 16) )
	{
		/* Search by KeyID */

	}
	else
	{
		/* Search by Text Regex */

	}

	return rslt;
}


int  retrieve_key_info(PGconn *conn, char *fingerprint)
{
	PGresult *result0 = NULL;
	PGresult *result1 = NULL;

	unsigned int nts = 0;

	char query0[200];
	char query1[155];
	unsigned char buff[650];


	snprintf(query0,199,"select fp, key_id, algorithm, size, c_time, e_time, revoked from \
                           cks_key_info_table where fp='%s'", fingerprint);
	snprintf(query1,150,"select  DISTINCT(uid) from cks_uid_table where fp='%s'", fingerprint);

	result0 = PQexec(conn, query0);
	if((PQresultStatus(result0) != PGRES_TUPLES_OK) && (PQresultStatus(result0) != PGRES_COMMAND_OK))
	{
		fprintf(stderr,_("search.c:  Command didn't return tuples properly.\n"));
		fprintf(stderr,_("search.c:  Failing Query: %s\n"),query0);
		PQclear(result0);
		db_exit_nicely(conn);
	}
	if(PQntuples(result0) == 0)
	{
		printf(_("Error:  No Records Found.\n"));
		printf("<br></br>\n");
		printf(_("A Database error Occured.\n"));
		printf(_("Child records appear to be missing.\n"));
		printf(_("Logging Internal Data Corruption...\n"));
		printf(_("Please try another key, or try the same key on another server.\n"));
	}
	else
	{
		result1 = PQexec(conn, query1);
		if((PQresultStatus(result1) != PGRES_TUPLES_OK) && (PQresultStatus(result1) != PGRES_COMMAND_OK))
		{
			fprintf(stderr, _("search.c:  Command didn't return tuples properly.\n"));
			fprintf(stderr, _("search.c:  Failing Query: %s\n"),query1);
			PQclear(result1);
			db_exit_nicely(conn);
		}
		nts = PQntuples(result1);
		if(nts == 0)
		{
			printf(_("No Records Found.\n"));
		}
		else
		{
			int i = 0;
			int revoked = 0;
			unsigned char algo[4];
			unsigned char algo_id = 0x00;
			long expiration_time = 0;
			long creation_time = 0;
			unsigned char creation_time_str[27];
			long current_time = 0;

			current_time = time(NULL);
			memset(creation_time_str,0x00,27);

			algo_id = atoi(PQgetvalue(result0,0,2));
			set_pk_algo_type(algo_id,algo);

			creation_time = 0;
			expiration_time = 0;
			revoked = 0;

			creation_time = atol(PQgetvalue(result0,0,4));
			expiration_time = atol(PQgetvalue(result0,0,5));
			revoked = atoi(PQgetvalue(result0,0,6));

			printf("<pre>\n");
			if(revoked == 1)
			{
				printf(_("<h3><font color=\"RED\">* KEY REVOKED *</font></h3>\n"));
			}
			if( (expiration_time != 0) && (current_time >= expiration_time) )
			{
				printf(_("<h3><font color=\"RED\">* KEY EXPIRED *</font></h3>\n"));
			}
			printf(_("Key ID           Algorithm/Size     Creation Time"));
			if(expiration_time != 0)
			{
				printf(_("                   Expiration Time"));
			}
			printf("\n");
			printf("0x%s       %s/%s           ", PQgetvalue(result0,0,1),algo,PQgetvalue(result0,0,3));

			if(expiration_time != 0)
			{
				creation_time_str[0] = '\0';
				snprintf(creation_time_str,26,"%s",ctime(&(creation_time)));
				creation_time_str[26] = '\0';
				printf("%s        %s",creation_time_str, ctime(&(expiration_time)));
			}
			else
			{
				printf("%s", ctime(&(creation_time)));
			}

			printf("\n");
			printf(_("<li>Fingerprint: <a href=\"search.cgi?stype=fp&fp="));
			printf("%s\">",fingerprint);
			print_fp(fingerprint);
			printf("</a></li>\n");
			printf("<ul>\n");

			for(i=0;i<nts;i++)
			{
				printf(_("\n<li>User ID: "));
				strncpy(buff,PQgetvalue(result1,i,0),649);
				print_sig_data(buff);
				printf("</li>\n");
				buff[0]='\0';
			}
			printf("</ul>\n");
			printf("</pre>\n");
			printf("<hr size=\"1\" width=\"100%%\">\n");
			fflush(0);
		}
	}

	PQclear(result0);
	PQclear(result1);
	printf("\n");


	return 0;
}


int  retrieve_key(PGconn *conn, char *fingerprint, unsigned int full,struct cks_config *config)
{
	struct openPGP_keyring *keyring = NULL;
	struct openPGP_pubkey *key_result = NULL;

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
		fprintf(stderr,_("Failed to parse retrieved pubkey: %s\n"),fingerprint);

		return -1;
	}
	rslt = parse_packets(&key_result,D_SOURCE_SEARCH_CGI);
	if(rslt == -1)
	{
		fprintf(stderr,_("Failed to parse retrieved pubkey's packets: %s\n"),fingerprint);

		return -1;
	}

	if(full)
	{
		echo_key_info(conn,key_result);
		echo_radix_key(key_result,config);
	}
	else
	{
		printf("<pre>\n");
		printf("<hr size=\"1\" width=\"100%%\">\n");
		fflush(0);
		echo_abrev_key_info(conn,key_result);
	}

	if(key_result != NULL)
	{
        	free_pubkey(&key_result);
	}


        return rslt;
}

void print_pgp5_x509_note(void)
{
	printf(_("<b>Missing Key ID Packet</b>\n"));
	printf("<br></br>\n");
	printf(_("<p>PGP Version 5 neglected to attach a key id packet when\n"));
	printf(_("generating a signature with an x509 certificate.  Signatures\n"));
	printf(_("that do not include key id packets are rendered by the keyserver\n"));
	printf(_("software as having been make by a key with the id 0x00000000.</p>\n"));
	printf(_("<p>If your key has such a signature on it, you may want to delete it.</p>\n"));
	printf(_("<p>If you are currently using PGP software which failes to include\n"));
	printf(_("key id packets, please upgrade to a newer version of PGP.</p>\n"));
	printf("<br></br>\n");
}
