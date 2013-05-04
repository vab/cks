/* cks_export.c - openPGP Key Export Application main source file
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
 
#include "cks_export.h"


int main(int argc,char *argv[])
{
        struct  cks_config *config = NULL;

        PGconn          *conn = NULL;

	FILE 		*kr = NULL;

        PGresult        *result = NULL;
        struct          openPGP_pubkey *key_result = NULL;

	int rslt = 0;
	int rslt_2 = 0;
	unsigned long to_export = 0;
	unsigned long exported = 0;

	unsigned char fp[41];
	unsigned long i = 0;
	unsigned long j = 0;

	/* 50000 pubkeys per file. */
	unsigned long max_keys = 50000;
	unsigned int file_num = 0;
	unsigned char file_name[20];

	unsigned int arg = 0;
	unsigned int verbose = 0;


        config = (struct cks_config *)malloc(sizeof(struct cks_config));
	if(config == NULL)
	{
		fprintf(stderr,_("cks_export: Fatal Error:  Malloc Call Failed: Out of memroy.\n"));

		return -1;
	}
        rslt = init_config(&config);
        if(rslt == -1)
        {
                fprintf(stderr,_("cks_export:  Non-Fatal Error: Failed to read config.\n"));
                fprintf(stderr,_("cks_export:  Using default configuration information.\n"));
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
						printf("Usage: cks_export\n");
						printf("	-v Verbose Mode\n");
						printf("	-h This Help Text\n");
						printf("	--help This Help Text\n");
						printf("	--version Display Version Information\n");
						printf("\n");

						return 0;
					}
					else if(strstr(argv[arg],"version") != NULL)
					{
						printf("CKS Version 0.2.2\n");

						return 0;
					}
				}
				else if(argv[arg][1] == 'v')
				{
					verbose = 1;
				}
				else
				{
					printf("Usage: cks_export\n");
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


	/* open the export file */
	if((kr = fopen("cks_ring-000.pgp","wb")) == NULL)
        {
                fprintf(stderr,_("cks_export: Failed to open file export_ring.pgp\n"));
		free(config);

                return -1;
        }

        /* Make the DB Connection. */
        conn = db_connect(config);
        if(conn == NULL)
        {
                fprintf(stderr,_("cks_export: Failed to connect to postgres database"));
                fprintf(stderr,_("cks_export: Connection to database failed.\n"));
                fprintf(stderr,"cks_export: %s", PQerrorMessage(conn));
		if(config != NULL)
		{
			free(config);
		}

                return -1;
        }


	result = PQexec(conn,"select fp from cks_fp_key_table\n");
	if(PQresultStatus(result) != PGRES_TUPLES_OK)
	{
		fprintf(stderr,_("cks_export:  Failed to return tuples.\n"));
		fprintf(stderr,_("cks_export:  Offending Query: select fp from cks_fp_key_table\n"));
		PQclear(result);
        	db_disconnect(conn);
		if(config != NULL)
		{
			free(config);
		}

		return -1;
	}

	to_export = PQntuples(result);
        if(to_export == 0)
        {
                fprintf(stderr, _("cks_export:  No Records Found.\n"));
		fprintf(stderr,_("cks_export:  Offending Query: select fp from cks_fp_key_table\n"));
                PQclear(result);
        	db_disconnect(conn);
		if(config != NULL)
		{
			free(config);
		}

		return -1;
        }


        printf(_("cks_export:  exporting %lu keys.\n"),to_export);
	printf(_("0 of %lu keys exported.\n"),to_export);

	for(i=0;i<to_export;i++)
	{
		key_result = retrieve_pubkey(conn,PQgetvalue(result,i,0),0);
		rslt_2 = parse_pubkey(&key_result,0);
		if(rslt_2 != 0)
		{
			free_pubkey(&key_result);
			continue;
		}
		rslt_2 = parse_packets(&key_result,0);
		if(rslt_2 != 0)
		{
			/* Thank you. Drive Through. */
			free_pubkey(&key_result);
			continue;
		}

		/* Write the key to the out file.  */
		rslt_2 = decode_radix(key_result);
		if(rslt_2 != 0)
		{
			free_pubkey(&key_result);
			continue;
		}
		/* TODO:  Speed this up with fwrite, it's fine for now though. */
		for(j=0;j<key_result->buffer_idx;j++)
		{
			/* TODO: Check for success here. */
			fputc(key_result->buffer[j],kr);
		}
		exported++;
		if((exported % 5000) == 0)
		{
			printf(_("%lu of %lu keys exported.\n"),exported,to_export);
		}
		/* If i is divisable by max_keys (default: 50,000), open a new file */
		if((exported % max_keys) == 0)
		{
			fclose(kr);
			file_num++;
			snprintf(file_name,19,"cks_ring-%03d.pgp",file_num);
			if((kr = fopen(file_name,"wb")) == NULL)
			{
				fprintf(stderr,_("cks_export: Failed to open file %s\n"),file_name);
				PQclear(result);
        			db_disconnect(conn);
				if(config != NULL)
				{
					free(config);
				}

				return -1;
			}
		}
		free_pubkey(&key_result);
	}

	/* Finish.  Clean up memory and exit. */
	PQclear(result);
        db_disconnect(conn);

        fclose(kr);

	if(config != NULL)
	{
		free(config);
	}


	return 0;
}
