/* cks_sync.c - Synchronization Application main source file
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

#include "cks_sync.h"


int main(int argc, char *argv[])
{
        struct keys_to_sync *keys = NULL;
        struct keys_to_sync *new_key = NULL;
        struct keys_to_sync *first_key = NULL;
        struct keys_to_sync *next_key = NULL;
	struct servers_to_sync *servers = NULL;
	struct servers_to_sync *new_server = NULL;
	struct servers_to_sync *first_server = NULL;
	struct servers_to_sync *next_server = NULL;
        int i = 0;

        struct  cks_config *config = NULL;

	FILE		*data_log = NULL;
        FILE            *err_log = NULL;

        PGconn          *conn = NULL;
        PGresult        *result_1 = NULL;
	PGresult	*result_2 = NULL;

        struct openPGP_pubkey      *pubkey = NULL;

        const char pks_servers_query[] = "select server from cks_other_servers order by sync_priority";
        const char keys_query[] = "select fp from cks_pending_sync";

	unsigned int	num_srvrs = 0;

	unsigned int arg = 0;
	unsigned int verbose = 0;

	int	rslt = 0;
	FILE  *socket = NULL;


        config = (struct cks_config *)malloc(sizeof(struct cks_config));
	if(config == NULL)
	{
		fprintf(stderr,_("cks_sync: malloc call failed: out of memroy!\n"));

		return -1;
	}
        rslt = init_config(&config);
        if(rslt == -1)
        {
                fprintf(stderr,_("cks_sync:  Non-Fatal Error: Failed to read config.\n"));
                fprintf(stderr,_("cks_sync:  Using default configuration information.\n"));
        }
	if(argc > 0)
	{
		for(arg=1;arg<argc;arg++)
		{
			if(argv[arg][0] == '-')
			{
				if(argv[arg][1] == '-')
				{
					if(strstr(argv[arg],"help") != NULL)
					{
						printf("Usage: cksd\n");
						printf("	-v Verbose Mode\n");
						printf("	-h This Help Text\n");
						printf("	--help This Help Text\n");
						printf("	--version Display Version Information\n");
						printf("\n");

						return 0;
					}
					else if(strstr(argv[arg],"version") != NULL)
					{
						printf("CKS Version 0.2.5\n");

						return 0;
					}
				}
				else if(argv[arg][1] == 'v')
				{
					verbose = 1;
				}
				else
				{
					printf("Usage: cks_sync\n");
					printf("	-v Verbose Mode\n");
					printf("	-h This Help Text\n");
					printf("	--help This Help Text\n");
					printf("	--version Display Version Information\n");
					printf("\n");

					return 0;

				}
			}
		}
	}
	if((err_log = fopen(config->err_log, "a")) == NULL)
        {
		fprintf(stderr,_("cks_sync:  Fatal Error:  Failed to open error log\n"));
                fprintf(stderr,_("cks_sync:  File open failed on: %s\n"),config->err_log);
		if(config != NULL)
			free(config);

                return -1;
        }

	if((data_log = fopen(config->data_log, "a")) == NULL)
        {
		fprintf(err_log,_("cks_sync:  Non-Fatal Error:  Failed to open data log.\n"));
                fprintf(err_log,_("cks_sync:  File open failed on: %s\n"),config->data_log);
		if(config != NULL)
			free(config);

		return -1;
        }
	
	/* Make the DB Connection. */
	conn = db_connect(config);
        if(conn == NULL)
	{
		fprintf(stderr,"Failed to connect to the db.\n");
		if(config != NULL)
			free(config);

		return -1;
	}

	/* Get The PKS Servers */
        result_1 = PQexec(conn, pks_servers_query);
        if (PQresultStatus(result_1) != PGRES_TUPLES_OK)
        {
                fprintf(err_log, _("cks_sync:  Fatal Error.\n"));
                fprintf(err_log, "cks_sync:  \n");
                fprintf(err_log, _("cks_sync:  Database Command didn't return tuples properly\n"));
                fprintf(err_log, "cks_sync:  \n");
                fprintf(err_log, _("cks_sync:  A query attempting to pull records from the\n"));
                fprintf(err_log, _("cks_sync:  cks_other_servers table failed due to a database\n"));
                fprintf(err_log, _("cks_sync:  error.  Please make sure postgreSQL is running, and\n"));
                fprintf(err_log, _("cks_sync:  that the cks_other_servers table exists.\n"));
                PQclear(result_1);

                db_exit_nicely(conn);
        }
	if(PQntuples(result_1) == 0)
	{
		fprintf(err_log, _("cks_sync:  Fatal Error.\n"));
                fprintf(err_log, "cks_sync:  \n");
                fprintf(err_log, _("cks_sync:  No Server Records where found in your cks_other_servers table.\n"));
                fprintf(err_log, "cks_sync:  \n");
                fprintf(err_log, _("cks_sync:  The table cks_other_servers should contain a list of other\n"));
                fprintf(err_log, _("cks_sync:  keyservers which this program will synchronize the updates to\n"));
                fprintf(err_log, _("cks_sync:  your keyserver database with.  There is no reason to run the\n"));
                fprintf(err_log, _("cks_sync:  sync program if the cks_other_servers table is empty.\n"));
                fprintf(err_log, "cks_sync:  \n");
                fprintf(err_log, _("cks_sync:  For content for the cks_other_servers table, you can contact\n"));
                fprintf(err_log, "cks_sync:  V. Alex Brennen [vab@cryptnet.net]\n");
                fprintf(err_log, "cks_sync:  http://www.cryptnet.net/people/vab/\n");
                PQclear(result_1);

                db_exit_nicely(conn);
	}
	else
	{
		num_srvrs = PQntuples(result_1);
		
		for(i = 0; i < num_srvrs; i++)
		{
			#ifdef DEBUG
			printf("cks_sync: adding server: %s\n",PQgetvalue(result_1,i,0));
			#endif
            /* Add server to a linked list */
		}
	}
        PQclear(result_1);
	/* End of building PKS List */

	/* Build the key list */
	result_2 = PQexec(conn, keys_query);
	if (PQresultStatus(result_2) != PGRES_TUPLES_OK)
	{
		fprintf(err_log, _("cks_sync:  Fatal Error.\n"));
		fprintf(err_log, "cks_sync:  \n");
		fprintf(err_log, _("cks_sync:  Database Command didn't return tuples properly\n"));
		fprintf(err_log, "cks_sync:  \n");
		fprintf(err_log, _("cks_sync:  A query attempting to pull records from the\n"));
		fprintf(err_log, _("cks_sync:  cks_pending_sync table failed due to a database\n"));
		fprintf(err_log, _("cks_sync:  error.  Please make sure postgreSQL is running, and\n"));
		fprintf(err_log, _("cks_sync:  that the cks_other_servers table exists.\n"));

		PQclear(result_2);

		db_disconnect(conn);
		if(config != NULL)
			free(config);
		
		return -1;
	}
	else if(PQntuples(result_2) == 0)
	{
		fprintf(err_log, _("cks_sync:  Non-Fatal Error.\n"));
                fprintf(err_log, "cks_sync:  \n");
                fprintf(err_log, _("cks_sync:  No Keys pending synch.\n"));
                fprintf(err_log, _("cks_sync:  Exiting...\n"));

                PQclear(result_2);

		db_exit_nicely(conn);
		if(config != NULL)
			free(config);

		return -1;
	}
	else
	{
		for(i = 0; i < PQntuples(result_2); i++)
		{
			new_key = (struct keys_to_sync *) malloc(sizeof(struct keys_to_sync));
			if(new_key == NULL)
			{
				fprintf(stderr,_("cks_mail_util: malloc call failed: out of memory!\n"));
				if(config != NULL)
					free(config);

				return -1;
			}
			strncpy(new_key->fp,PQgetvalue(result_2,i,0),41);
			if(keys == NULL)
			{
				keys = new_key;
				keys->next = NULL;
				first_key = keys;
			}
			else
			{
				keys->next = new_key;
				keys = new_key;
				keys->next = NULL;
			}
		}
	}
	PQclear(result_2);
	/* end of building key list */

        keys = first_key;
	while(keys != NULL)
	{
		int result = 0;
		unsigned long len = 0;
		int j = 1;
		
		/*  retrieve the pubkey from the db */
		pubkey = (struct openPGP_pubkey *)retrieve_pubkey(conn,keys->fp,D_SOURCE_CKS_SYNC_UTIL);
		if(pubkey == NULL)
		{
			fprintf(stderr,_("Failed to retrieve key: %s\n"),keys->fp);

			fclose(data_log);
			if(config != NULL)
				free(config);

			return -1;
		}


		/* open up a socket */
		

		/* Send the key over http */

		fprintf(socket,"-----BEGIN PGP PUBLIC KEY BLOCK-----\n");
		fprintf(socket,"%s",config->vrsn);
		fprintf(socket,"%s",config->cmnt);

		len = strlen(pubkey->radix_data);
		if(len == 0)
		{
			fprintf(stderr,"Error Detected: Unable to echo radix key. Key returns radix length of 0.\n");
		}
		else
		{
			j = 1;
			for(i=0;i<len;i++)
			{
				fprintf(socket,"%c",pubkey->radix_data[i]);
				if(j == 64) fprintf(socket,"\n");
				else if((j % 64) == 0) fprintf(socket,"\n");
				j++;
			}
			if((j % 64) != 1) fprintf(socket,"\n");
		}
		fprintf(socket,"=%s\n",pubkey->encoded_cksum);
		fprintf(socket,"-----END PGP PUBLIC KEY BLOCK-----\n");
		fprintf(socket,"\n\n");

		/* close socket */

		/* Next server */
		remove_key_from_sync_list(conn,keys->fp,err_log);

		free_pubkey(&pubkey);

		keys = keys->next;
	}

        db_disconnect(conn);
	fclose(data_log);

	/* Free Memory */
        keys = first_key;
        while(keys != NULL)
        {
                next_key = keys->next;
                free(keys);
                keys = next_key;
        }

	if(config != NULL)
	{
        	free(config);
	}

        fclose(err_log);


	return 0;
}
