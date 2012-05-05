/* retrieve.c - openPGP key retrieval functions
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

#include "retrieve.h"


struct openPGP_pubkey * retrieve_pubkey(PGconn *conn,unsigned char *fingerprint,int source)
{
	PGresult        *result = NULL;
	char            stmt[112];
	struct          openPGP_pubkey *key_result = NULL;
	unsigned char   *radix_key = NULL;

	int rslt = 0;

	/* OID Stuff */
	int r_res = 0;
	int p_res = 0;
	Oid key_oid;
	int key_fd = 0;
	int total_bytes = 0;
	unsigned char buff[1024];
	/* End OID Stuff */


	if(conn == NULL)
	{
		fprintf(stderr,"A null database connection was passed to retrieve pubkey.\n");
		
		return NULL;
	}

	if((strlen(fingerprint) != 40) && (strlen(fingerprint) != 32))
	{
		fprintf(stderr,_("retrieve.c: apparently malformed fingerprint. Length not 32 or 40. fp: %s\n"),fingerprint);

		return NULL;
	}

	memset(stmt,0x00,112);
	memset(buff,0x00,1024);

	key_result = (struct openPGP_pubkey *)malloc(sizeof(struct openPGP_pubkey));
	if(key_result == NULL)
	{
		fprintf(stderr,_("retrieve.c: malloc call failed: out of memory\n"));

		return NULL;
	}
	rslt = init_openPGP_pubkey(&key_result,D_CKS_MAX_LEN);
	if(rslt == -1)
	{
		fprintf(stderr,_("Call to init_openPGP_pubkey failed in retrieve_pubkey\n"));
		if(key_result != NULL)
		{
			free_pubkey(&key_result);
		}

		return NULL;
	}

	key_result->radix_key = (unsigned char *)malloc(D_CKS_MAX_LEN);
	if(key_result->radix_key == NULL)
	{
		fprintf(stderr,_("retrieve.c: key_result->radix_key: Out of Memory: malloc call failed!\n"));
		if(key_result != NULL)
		{
			free_pubkey(&key_result);
		}

		return NULL;
	}
	memset(key_result->radix_key,0x00,D_CKS_MAX_LEN);
	
	radix_key = (unsigned char *)malloc(D_CKS_MAX_LEN);
	if(radix_key == NULL)
	{
		fprintf(stderr,_("retrive.c: malloc radix_key: Out of Memory: malloc call failed!\n"));
		if(key_result != NULL)
		{
			free_pubkey(&key_result);
		}

		return NULL;
	}
	memset(radix_key,0x00,D_CKS_MAX_LEN);


	if(db_begin_transaction(conn) == -1)
	{
		fprintf(stderr,_("retrieve.c: Postgres operation start COMMIT segment failed\n"));
		if(key_result->radix_key != NULL)
			free_pubkey(&key_result);
		if(radix_key != NULL)
			free(radix_key);

		return NULL;
	}

	snprintf(stmt,110,"select fp, ecsum, pgp_key from cks_fp_key_table where fp='%s'",fingerprint);
	result = PQexec(conn, stmt);
	if(PQresultStatus(result) != PGRES_TUPLES_OK)
	{
		fprintf(stderr, _("retrieve.c:  Failed to return tuples.\n"));
		fprintf(stderr, _("retrieve.c:  Offending Query: %s\n"), stmt);
		PQclear(result);

		if(key_result != NULL)
			free_pubkey(&key_result);
		if(radix_key != NULL)
			free(radix_key);

		return NULL;
	}

	if(PQntuples(result) == 0)
	{
		fprintf(stderr, _("retrieve.c:  No Records Found.\n"));
		fprintf(stderr, _("retrieve.c:  Offending Query: %s\n"), stmt);
		PQclear(result);

		if(key_result != NULL)
			free_pubkey(&key_result);
		if(radix_key != NULL)
			free(radix_key);

		return NULL;
	}

	strncpy(key_result->encoded_cksum,PQgetvalue(result,0,1),4);
	key_result->encoded_cksum[4] = '\0';
	strncpy(buff,PQgetvalue(result,0,2),12);
	key_oid = (Oid)atoi(buff);
	/* http://www.postgresql.org/docs/8.4/interactive/lo-interfaces.html */
	key_fd = lo_open(conn,key_oid,INV_READ);
	if(key_fd < 0)
	{
		fprintf(stderr,"retrieve.c 157: Failed to open the large object.\n");
		
		return NULL;
	}
	r_res = 1;
	while(r_res != 0)
	{
		memset(buff,0x00,1024);
		/* TODO: lo_read returns a negative value on error. */
		r_res = lo_read(conn,key_fd,buff,1024);
		if(r_res == 0)
			break;
		if(r_res < 0)
			break;
		total_bytes = total_bytes + r_res;
		r_res++;
		if(r_res != 0)
			strncat(key_result->radix_data,buff,D_CKS_MAX_LEN - 1);
		key_result->radix_data[total_bytes] = '\0';
	}
	/* TODO: lo_close returns 0 on success */
	lo_close(conn,key_fd);
	PQclear(result);

	if(db_commit_transaction(conn) == -1)
	{
		fprintf(stderr,_("retrieve.c: Postgres operation end COMMIT segment failed\n"));
		if(key_result != NULL)
			free_pubkey(&key_result);
		if(radix_key != NULL)
			free(radix_key);

		return NULL;
	}

	p_res = process_ebuff_ecsum_pubkey(key_result,source);
	if(p_res == -1)
	{
		int rslt = 0;
		
		printf("process_ebuff_ecsum_pubkey failed!\n");
		fflush(0);
		fprintf(stderr,_("Pubkey parse failed: %s.\n"), fingerprint);
		fprintf(stderr,_("Attempting to delete corrupted key from db.\n"));
		rslt = purge_corrupt_key_from_db(conn,fingerprint,0);
		if(rslt == -1)
		{
			fprintf(stderr,_("Failed to purge corrupt key from database: %s\n"),fingerprint);
		}
		if(key_result != NULL)
			free_pubkey(&key_result);
		if(radix_key != NULL)
			free(radix_key);

		return NULL;
	}
	if(radix_key != NULL)
		free(radix_key);

	return key_result;
}


/*  Check and see if the key_exists in the keyserver database.
    Return 1 if it does, 0 if it does not and -1 on error.
*/
int key_exists(PGconn *conn,unsigned char *fp)
{
	int key_exists = -1;

	PGresult        *result = NULL;
	char            fp_query[112];


	if((strlen(fp) != 40) && (strlen(fp) != 32))
	{
		fprintf(stderr,_("retrieve.c: apparently malformed fingerprint in key exists query. Length not 32 or 40. fp: %s\n"),fingerprint);

		return -1;
	}

	memset(fp_query,0x00,112);
	snprintf(fp_query,110,"select fp from cks_fp_key_table where fp='%s'", fp);

	result = PQexec(conn, fp_query);
	if(!result)
	{
		fprintf(stderr,_("retrieve.c: Postgres operation to check if key exists failed with query:\n"));
		fprintf(stderr,_("retrieve.c: %s\n"),fp_query);

		return -1;
	}
	if(PQresultStatus(result) != PGRES_TUPLES_OK)
	{
		do_error_page(_("retrieve.c:  Error:  Bad Tuples.\n"));
		fprintf(stderr,_("retrieve.c: Offending Query: %s\n"), fp_query);
		PQclear(result);

		return -1;
	}
	if(PQntuples(result) == 0)
	{
		key_exists = 0;
	}
	else if(PQntuples(result) == 1)
	{
		key_exists = 1;
	}
	PQclear(result);


	return key_exists;
}

int key_rejected(PGconn *conn,unsigned char *fp)
{
	int key_rejected = 0;

	PGresult        *result = NULL;
	char            fp_query[122];

	int rslt = 0;

	
	if((strlen(fp) != 40) && (strlen(fp) != 32))
	{
		fprintf(stderr,_("retrieve.c: apparently malformed fingerprint in key rejected query. Length not 32 or 40. fp: %s\n"),fingerprint);

		return -1;
	}
	
	memset(fp_query,0x00,122);
	snprintf(fp_query,111,"select fp from cks_rejected_keys where fp='%s'", fp);
	result = PQexec(conn, fp_query);
	if(!result)
	{
		fprintf(stderr,_("retrieve.c: Postgres operation to check if key is rejected failed with query:\n"));
		fprintf(stderr,_("retrieve.c: %s\n"),fp_query);

		return -1;
	}
	if(PQresultStatus(result) != PGRES_TUPLES_OK)
	{
		do_error_page(_("retrieve.c:  Error:  Bad Tuples.\n"));
		fprintf(stderr,_("retrieve.c: Offending Query: %s\n"), fp_query);
		PQclear(result);

		return -1;
	}
	if(PQntuples(result) == 1)
	{
		key_rejected = 1;
	}
	PQclear(result);


	return key_rejected;
}

int retrieve_off_network_by_id(unsigned char *keyid)
{
	/* The idea here is that we'll do a socket based pks search
	   against the other major networks: PKS,SKS,Keyserver.net,
	   PGP.com and attempt to retrieve keys by keyid */

	/* TODO: not yet implemented.  planned for version 2.0.0. */


	return 0;
}

int retrieve_off_network_by_fp(unsigned char *fp)
{
	/* The idea here is that we'll do a socket based pks search
	   against the other major networks: PKS,SKS,Keyserver.net,
	   PGP.com and attempt to retrieve keys by fingerprint */

	/* TODO: not yet implemented.  planned for version 2.0.0. */

	return 0;
}
