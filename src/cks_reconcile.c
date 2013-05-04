/* cks_reconcile.c - Synchronization Reconciliation main source file
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

#include "cks_reconcile.h"


int main(int argc, char *argv[])
{
        struct  cks_config *config = NULL;

        PGconn          *conn = NULL;
        PGresult        *result = NULL;
	
	unsigned	long	to_export = 0;
	unsigned 	long	i = 0;
	
	int	rslt = 0;

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
					printf("Usage: cksd\n");
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
	
	
	for(i=0;i<to_export;i++)
	{
	
	}
	
	build_full_key_list();
	send_key_list();
	
	/* Finish.  Clean up memory and exit. */
	PQclear(result);
        db_disconnect(conn);
	
	if(config != NULL)
	{
		free(config);
	}

	
	return 0;
}


int build_full_key_list(void)
{
	/* We should pass it a null linked list here and return a pointer to mallocd memory.  We can 
	   then walk the linked list in the program and free it when we are finished.  With a usage 
	   of 40 bytes per key and an estimation of 2million keys, we're looking at 80million bytes 
	   of ~8 megabytes.  While that is a tremendous amount, it is well with the acceptable range
	   of usage for a program which is infrequently run. */
}


int perform_reconciliation(struct d_linked_list *list_local, struct d_linked_list *list_foreign)
{
	/* This needs to be moved to cks_common or some other place so that it can be called by cksd.
	   We want cksd to open a stocket to the sync target cksd and dump any keys not listed.
	 */
	struct d_linked_list *walk_local = NULL;
	struct d_linked_list *walk_foreign = NULL;

	char *foreign_address;

	int found = 0;
	int rslt = 0;

	walk_local = get_first_dll_node(list_local);
	while(walk_local != NULL)
	{
		found = 0;

		walk_foreign = get_first_dll_node(list_foreign);
		while(walk_foreign != NULL)
		{
			if(strcmp(walk_local->name,walk_foreign->name) == 0)
			{
				found = 1;
				break;
			}
			walk_foreign = walk_foreign->next;
		}
		if(found == 0)
		{
			printf("Requesting:  %s\n", (char *)walk_local->name);
			/*rslt = fetch_from(walk_local->name,foreign_address);
			if(rslt == -1)
			{
				fprintf(stderr,"Failed to fetch key %s\n",walk_local->name);
			}*/
		}
	 	walk_local = walk_local->next;
	} 
	return 0;
}


int transmit_reconciliation_keys(void)
{

	return 0;
}

int send_key_list(void)
{

	return 0;
}

