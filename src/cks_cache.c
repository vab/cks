/* cks_cache.c - CKS Key cache routines source file
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

#include "cks_cache.h"


int load_cache(PGconn *conn,struct d_linked_list **cache)
{
	struct d_linked_list *walk_list = NULL;
	int rslt = 0;

	walk_list = get_first_dll_node(*cache);
	while(walk_list != NULL)
	{
		walk_list->value = (struct openPGP_pubkey *)retrieve_pubkey(conn,walk_list->name,D_SOURCE_CKSD);
		if(walk_list->value == NULL)
		{
			fprintf(stderr,"Error retreiving key from database in cache load\n");

			return -1;
		}
		walk_list->keyid = malloc(10);
		if(walk_list->keyid == NULL)
		{
			fprintf(stderr,"Malloc call failed.\n");

			return -1;
		}
		memcpy(walk_list->keyid,((char *)((struct openPGP_pubkey *)walk_list->value)->keyid_t),9);
		walk_list->lkeyid = malloc(18);
		if(walk_list->lkeyid == NULL)
		{
			fprintf(stderr,"Malloc call failed.\n");

			return -1;
		}
		memcpy(walk_list->lkeyid,((char *)((struct openPGP_pubkey *)walk_list->value)->fkeyid_t),17);
		printf("Loaded into cache: %s\n",(unsigned char *)walk_list->name);
		walk_list = walk_list->next;
	}

	return rslt;
}


struct openPGP_pubkey * search_cache(struct d_linked_list *cache,char *st)
{
	struct openPGP_pubkey *pubkey = NULL;
	struct d_linked_list *walk_list = NULL;
	int rslt = 0;
	unsigned int stl = 0;

	stl = strlen(st);
	walk_list = get_first_dll_node(cache);
	while(walk_list != NULL)
	{
		if(stl == 8)
		{
			rslt = memcmp(((struct openPGP_pubkey *)walk_list->value)->keyid_t,st,8);
			if(rslt == 0)
			{
				return ((struct openPGP_pubkey *)walk_list->value);
			}
		}
		else if(stl == 16)
		{
			rslt = memcmp(((struct openPGP_pubkey *)walk_list->value)->fkeyid_t,st,16);
			if(rslt == 0)
			{
				return ((struct openPGP_pubkey *)walk_list->value);
			}
		}
		else if(stl == 32)
		{
			rslt = memcmp(((struct openPGP_pubkey *)walk_list->value)->fp,st,32);
			if(rslt == 0)
			{
				return ((struct openPGP_pubkey *)walk_list->value);
			}
		}
		else if(stl == 40 )
		{
			rslt = memcmp(((struct openPGP_pubkey *)walk_list->value)->fp,st,40);
			if(rslt == 0)
			{
				return ((struct openPGP_pubkey *)walk_list->value);
			}
		}

		walk_list = walk_list->next;
	}

	/* if key is not in cache, return NULL */
	return NULL;
}

int free_cache(struct d_linked_list **cache)
{
	struct d_linked_list *tmp_ptr = NULL;
	struct d_linked_list *walk_ptr = NULL;

	walk_ptr = get_first_dll_node((*cache));
	while(walk_ptr != NULL)
	{
		tmp_ptr = walk_ptr->next;
		if(walk_ptr->value != NULL)
		{
			free_pubkey((struct openPGP_pubkey **)&(walk_ptr->value));
		}
		if(walk_ptr->keyid != NULL)
		{
			free(walk_ptr->keyid);
		}
		if(walk_ptr->lkeyid != NULL)
		{
			free(walk_ptr->lkeyid);
		}
		free(walk_ptr);

		walk_ptr = tmp_ptr;
	}

	return 0;
}
