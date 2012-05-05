/* keys.c - openPGP key processing functions
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

#include "keys.h"


int echo_abrev_key_info(PGconn *conn,struct openPGP_pubkey *key_result)
{
	struct user_id *walk_id = NULL;


	if((conn == NULL) || (key_result == NULL))
	{
		fprintf(stderr,"echo_abrev_key_info was passed a null arg.\n");

		return -1;
	}

	key_result_validate(key_result);

	echo_key_main_key_info(key_result);

	walk_id = (struct user_id *)get_first_uid(key_result->ids);
	if(walk_id == NULL)
	{
		fprintf(stderr,"Error: call to get_first_uid in echo_abrev_key_info retured NULL.\n");
		
		return -1;
	}
	printf("<ul>\n");
	while(walk_id != NULL)
	{
		if(walk_id->revoked == 1)
		{
			printf(_("<p><font color=\"red\">User ID Revoked</font></p>\n"));
		}
		printf(_("<li>User ID: "));
		print_sig_data(walk_id->id_data);
		printf("</li>\n");
		fflush(0);
		walk_id = walk_id->next;
	}
	printf("</ul>\n");
	printf("</pre>\n");
	fflush(0);

	return 0;
}


int echo_key_info(PGconn *conn,struct openPGP_pubkey *key_result)
{
	struct user_id *walk_id = NULL;
	struct key_signature *walk_sig = NULL;
	unsigned char keyid[9];
	unsigned char full_keyid[17];

	int result = 0;


	if((conn == NULL) || (key_result == NULL))
	{
		fprintf(stderr,"Null input to echo_key_info\n");

		return -1;
	}
	
	memset(keyid,0x00,9);
	memset(full_keyid,0x00,17);

	result = key_result_validate(key_result);
	if(result == -1)
	{
		fprintf(stderr,_("Key_result_validate return invald!\n"));

		return -1;
	}

	echo_key_main_key_info(key_result);

	walk_id = (struct user_id *)get_first_uid(key_result->ids);
	if(walk_id == NULL)
	{
		fprintf(stderr,"keys.c: call to get_first_uid returned NULL in 	echo_key_info.\n");

		return -1;
	}
	printf("<ul>\n");
	while(walk_id != NULL)
	{
		if(walk_id->revoked == 1)
		{
			printf(_("<p><font color=\"red\">User ID Revoked</font></p>\n"));
		}
		printf("<li>User ID: ");
		if(walk_id->id_data != NULL)
		{
			print_sig_data(walk_id->id_data);
			printf("</li>\n");
		}
		if(walk_id->signatures != NULL)
		{
			walk_sig = (struct key_signature *)get_first_sig(walk_id->signatures);
			printf("<ul>\n");
			while(walk_sig != NULL)
			{
				/* This needs to be fixed to handle v3 Keys/Sigs */
				snprintf(full_keyid,17,"%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X",walk_sig->key_id[0],walk_sig->key_id[1],walk_sig->key_id[2],walk_sig->key_id[3],walk_sig->key_id[4],walk_sig->key_id[5],walk_sig->key_id[6],walk_sig->key_id[7]);
				snprintf(keyid,9,"%.8X",walk_sig->lkeyid);
				print_uid(conn,keyid,full_keyid);
				walk_sig = walk_sig->next;
			}
			printf("</ul>\n");
		}
			walk_id = walk_id->next;
	}
	printf("</ul>\n");
	if(key_result->subkeys != NULL)
	{
		printf(_("<li>Subkeys</li>\n"));
		printf("<ul>\n");
		echo_subkey_info(key_result,key_result->subkeys);
		printf("</ul>\n");
	}
	printf("</pre>\n");
	if(key_result->has_photo)
	{
		printf("<img src=\"cks_keyimg.cgi?%s\">\n",key_result->fp_db);
	}
	printf("<hr size=\"0\" width=\"100%%\">\n");
	printf("<a href=\"http://www.biglumber.com/x/web?sf=%s\">Look up this key on Big Lumber</a>\n",key_result->fp_db);
	fflush(0);

	return 0;
}


int key_result_validate(struct openPGP_pubkey *key_result)
{
	int status = 0;

	if(key_result == NULL)
	{
		status = -1;
	}
	else if(key_result->keyid_t == NULL)
	{
		status = -1;
	}
	else if(key_result->algo == NULL)
	{
		status = -1;
	}

	return status;
}


int echo_key_main_key_info(struct openPGP_pubkey *key_result)
{
	unsigned char creation_time[26];
	long current_time = 0;


	if(key_result == NULL)
	{
		fprintf(stderr,"echo_key_mail_key_info passed null arg.\n");

		return -1;
	}

	memset(creation_time,0x00,26);

	printf("<pre>\n");
	if(key_result->key_revoked == 1)
	{
		printf(_("<h3><font color=\"red\">* KEY REVOKED *</font></h3>\n"));
	}
	current_time = time(NULL);
	if((key_result->expiration_time != 0) && (current_time >= (key_result->expiration_time)))
	{
		printf(_("<h3><font color=\"red\">* KEY EXPIRED *</font></h3>\n"));
	}
	printf(_("Key ID           Algorithm/Size     Creation Time"));
	if(key_result->expiration_time != 0)
	{
		printf(_("                   Expiration Time"));
	}
	printf("\n");
	printf("0x%s       %s/%d           ", key_result->keyid_t, key_result->algo,key_result->key_size);

	if(key_result->expiration_time != 0)
	{
		snprintf(creation_time,25,ctime(&(key_result->creation_time)));
		creation_time[25] = '\0';
		printf("%s        %s",creation_time, ctime(&(key_result->expiration_time)));
	}
	else
	{
		printf("%s", ctime(&(key_result->creation_time)));
	}
	printf("\n");
	printf(_("<li>Fingerprint: <a href=\"search.cgi?stype=fp&fp="));
	printf("%s\">", key_result->fp_db);
	printf("%s</a></li>\n",key_result->fp_t);
	fflush(0);


	return 0;
}


int echo_subkey_info(struct openPGP_pubkey *the_key,struct openPGP_subkey *subkeys)
{
	struct openPGP_subkey *walk_subkey = NULL;
	struct key_signature *walk_signature = NULL;
	struct user_id *primary_id = NULL;


	if((subkeys == NULL) || (the_key == NULL))
	{
		fprintf(stderr,"echo_subkey_info passed null arg.\n");

		return -1;
	}
	walk_subkey = (struct openPGP_subkey *)get_first_subkey(subkeys);
	/* TODO: Check for null */
	/* TODO: I need to change this to get primary id instead of first id */
	primary_id = (struct user_id *)get_first_uid(the_key->ids);

	while(walk_subkey != NULL)
	{
		unsigned char creation_time[26];
		long current_time = 0;
		int i = 0;

		memset(creation_time,0x00,26);

		current_time = time(NULL);
		creation_time[0] = '\0';

		printf("<li>0x%s  %s/%d      ",walk_subkey->keyid_t,walk_subkey->algo,walk_subkey->key_size);

		if(walk_subkey->expiration_time != 0)
		{
			snprintf(creation_time,25,ctime(&(walk_subkey->creation_time)));
			creation_time[25] = '\0';
			printf("%s        %s",creation_time,ctime(&(walk_subkey->expiration_time)));
			printf("</li>");
		}
  		else
		{
			printf("%s",ctime(&(walk_subkey->creation_time)));
			printf("</li>");
		}

		if(walk_subkey->binding_signatures != NULL)
		{
			walk_signature =  (struct key_signature *)get_first_sig(walk_subkey->binding_signatures);
			printf("<ul>\n");
			while(walk_signature != NULL)
			{
				printf("<li>0x%.8X  ",walk_signature->lkeyid);
				print_sig_data(primary_id->id_data);
				printf("</li>\n");

				walk_signature = walk_signature->next;
			}
			printf("</ul>\n");
		}
		walk_subkey = walk_subkey->next;
	}
	fflush(0);


	return 0;
}


int add_keyring_to_db(PGconn *conn,struct openPGP_keyring *keyring, int source)
{
	struct openPGP_pubkey *walk_pubkey = NULL;

	int rslt = 0;
	int status = 0;


	if((keyring == NULL) || (keyring->pubkeys == NULL))
	{
		fprintf(stderr,"add_keyring_to_db passed null arg.\n");

		return -1;
	}

	walk_pubkey = (struct openPGP_pubkey *)get_first_pubkey(keyring->pubkeys);
	if(walk_pubkey == NULL)
		return -1;

	if(source == D_SOURCE_ADD_CGI)
	{
		print_header(_("<center>Keyring Addition Results</center>"));
		printf("<hr size=\"1\" width=\"100%%\">\n");
	}
	while(walk_pubkey != NULL)
	{
		rslt = add_key_from_keyring(conn,walk_pubkey,source);
		if(rslt == -1)
		{
			fprintf(stderr,"Failed to add key from keyring.\n");
			status = -1;
		}

		walk_pubkey = walk_pubkey->next;
	}
	if(source == D_SOURCE_ADD_CGI)
	{
		print_footer();
	}


	return status;
}


int add_key_from_keyring(PGconn *conn,struct openPGP_pubkey *walk_pubkey, int source)
{
	if((conn == NULL) || (walk_pubkey == NULL))
	{
		fprintf(stderr,"Null arg passed to add_key_from_keyring\n");

		return -1;
	}

	/* Check and make sure that this isn't a rejected key */
	if(key_rejected(conn,walk_pubkey->fp_db))
	{
		if(source == D_SOURCE_ADD_CGI)
		{
			printf(_("<h3>This key is in a list of rejected keys.</h3>"));
			echo_key_info(conn,walk_pubkey);
			printf(_("<p>If you would still like to add this key to the CryptNET\n"));
			printf(_("keyserver network, you'll need to contact the administrator\n"));
			printf(_("this server.  Preferably, you should sign your communication\n"));
			printf(_("with the secret key associated with the public key which you're\n"));
			printf(_("attempting to add.</p>\n"));
		}
	}
	else
	{
		if(key_exists(conn,walk_pubkey->fp_db))
		{
			struct openPGP_pubkey *retrieved_key;
			int rslt = 0;
			int keys_diff = 0;

			retrieved_key = (struct openPGP_pubkey *)retrieve_pubkey(conn,walk_pubkey->fp_db,source);
			if(retrieved_key == NULL)
			{
				int retry_rslt = 0;

				fprintf(stderr,_("Retrying key addition after purge: %s\n"),walk_pubkey->fp_db);
				retry_rslt = retry_key_addition_after_purge(conn,walk_pubkey);
				if(retry_rslt == -1)
				{
					fprintf(stderr,_("Retrieved key is null: %s.\n"),walk_pubkey->fp_db);
					fprintf(stderr,_("Key addition failed. Unable to purge!\n"));

					return -1;
				}
				else
				{
					return 0;
				}
			}
			rslt = parse_pubkey(&retrieved_key,source);
			if(rslt == -1)
			{
				fprintf(stderr,_("Failed to retrieve key from db: %s\n"),walk_pubkey->fp_db);

				return -1;
			}
			rslt = parse_packets(&retrieved_key,source);
			if(rslt == -1)
			{
				fprintf(stderr,_("keys.c:  Fail to parse_packets from ret key from db: %s\n"),walk_pubkey->fp_db);

				return -1;
			}
			/* compare keys */
			keys_diff = compare_keys(walk_pubkey,retrieved_key);
			if(keys_diff)
			{
				int result = 0;

				result = merge_keys(walk_pubkey,retrieved_key);
				if(result == -1)
				{
					if(source == D_SOURCE_ADD_CGI)
					{
						do_error_page(_("keys.c: Key Information Merge Failed.\n"));
						retrieved_key->key_status = -1;

						return -1;
					}
					else
					{
						fprintf(stderr,_("merge_keys failed for key: %s\n"),walk_pubkey->fp_db);
						retrieved_key->key_status = -1;

						return -1;
					}
				}
				result = build_new_radix_data(retrieved_key);
				if(result == -1)
				{
					if(source == D_SOURCE_ADD_CGI)
					{
						do_error_page(_("Radix encoding of new key failed.\n"));
						retrieved_key->key_status = -1;
						retrieved_key->radix_data = NULL;

						return -1;
					}
					else
					{
						fprintf(stderr,_("build_new_radix_data failed for key: %s\n"),walk_pubkey->fp_db);
						retrieved_key->key_status = -1;
						retrieved_key->radix_data = NULL;

						return -1;
					}
				}
				result = add_with_delete_key(conn,retrieved_key,source);
				if(result == -1)
				{
					if(source == D_SOURCE_ADD_CGI)
					{
						do_error_page(_("Failed to delete and insert key info database.\n"));

						return -1;
					}
				}
				if(walk_pubkey == NULL) printf(_("Key Result Is NULL\n"));
				if(source == D_SOURCE_ADD_CGI)
				{
					printf(_("<h3>New Key Information Merged.</h3>\n"));
					chk_key_version(walk_pubkey->key_version);
					echo_key_info(conn,retrieved_key);
				}
				free_pubkey(&retrieved_key);
			}
			else
			{
				if(source == D_SOURCE_ADD_CGI)
				{
					printf(_("<h3>Key Already in Database.</h3>"));
					chk_key_version(walk_pubkey->key_version);
					echo_key_info(conn,walk_pubkey);
				}
				free_pubkey(&retrieved_key);
			}
		}
		else
		{
			int result = 0;

			result = add_key_to_db(conn,walk_pubkey,source);
			if(result == -1)
			{
				if(source == D_SOURCE_ADD_CGI)
				{
					do_error_page(_("Failed To add key to db\n"));
				}
				else if(source == D_SOURCE_MAIL_SYNC)
				{
					fprintf(stderr,_("Failed to add key to db.\n"));
				}
			}
			else
			{
				if(source == D_SOURCE_ADD_CGI)
				{
					/*  Out put the Packet Information Here */
					printf(_("<h3>Public Key Added:</h3>"));
					chk_key_version(walk_pubkey->key_version);
					if(walk_pubkey == NULL) printf(_("Key Result is null\n"));
					echo_key_info(conn,walk_pubkey);
				}
			}
		}
	}

	return 0;
}


int db_add_pubkey(PGconn *conn,struct openPGP_pubkey *pubkey,int source)
{
	if((conn == NULL) || (pubkey == NULL))
	{
		fprintf(stderr,"Null arg passed to db_add_pubkey\n");

		return -1;
	}

	if(key_rejected(conn,pubkey->fp_db))
	{
		return D_KEY_REJECTED;
	}
	else
	{
		if(key_exists(conn,pubkey->fp_db))
		{
			struct openPGP_pubkey *retrieved_key;
			int rslt = 0;
			int keys_diff = 0;

			retrieved_key = (struct openPGP_pubkey *)retrieve_pubkey(conn,pubkey->fp_db,source);
			if(retrieved_key == NULL)
			{
				fprintf(stderr,"Retrieved key is null: %s.\n",pubkey->fp_db);

				return -1;
			}
			/* FIXME */
			rslt = parse_pubkey(&retrieved_key,source);
			if(rslt == -1)
			{
				fprintf(stderr,"key.c: parse_pubkey failed: %s\n",pubkey->fp_db);

				return -1;
			}
			rslt = parse_packets(&retrieved_key,source);
			if(rslt == -1)
			{
				fprintf(stderr,"key.c: parse_packets failed: %s\n",pubkey->fp_db);

				return -1;
			}
			/* compare keys */
			keys_diff = compare_keys(pubkey,retrieved_key);
			if(keys_diff)
			{
				int result = 0;

				/* TODO: I need to look at how this rejects if version is invalid. */
/*				chk_key_version(pubkey->key_version); */
				result = merge_keys(pubkey,retrieved_key);
				if(result == -1)
				{
					fprintf(stderr,"keys.c: db_add_pubkey: merge_keys failed: %s\n",pubkey->fp_db);
					free_pubkey(&retrieved_key);

					return -1;
					/* Tell the code: Don't add this key. */
				}
				if(result == 1)
				{
					result = build_new_radix_data(retrieved_key);
					if(result == -1)
					{
						fprintf(stderr,"keys.c: db_add_pubkey: build_new_radix_data failed (retrieved_key): %s\n",pubkey->fp_db);
						free_pubkey(&retrieved_key);

						return -1;
						/* Tell the code:  Don't add this key */
					}
					result = add_with_delete_key(conn,retrieved_key,source);
					if(result == -1)
					{
						fprintf(stderr,"keys.c: db_add_pubkey: Failed to add key:  %s\n",retrieved_key->fp_t);
						free_pubkey(&retrieved_key);

						return -1;
					}
					free_pubkey(&retrieved_key);

					return D_KEY_MERGED;
				}
				else
				{
					free_pubkey(&retrieved_key);

					return D_KEY_EXISTS;
				}
			}
			else
			{
				free_pubkey(&retrieved_key);
				
				return D_KEY_EXISTS;
			}
		}
		else
		{
			int result = 0;

			result = add_key_to_db(conn,pubkey,source);
			if(result == -1)
			{
				fprintf(stderr,"Failed to add key to db: %s.\n",pubkey->fp_db);

				return D_KEY_ADDITION_FAILED;
			}
			else
			{
				return D_KEY_ADDED;
			}
		}
	}


	return -1;
}


int add_key_to_db(PGconn *conn,struct openPGP_pubkey *pubkey,int source)
{
	int     result = 0;


	if((conn == NULL) || (pubkey == NULL))
	{
		fprintf(stderr,"null arg passed to add_key_to_db\n");

		return -1;
	}

	if(db_begin_transaction(conn) == -1)
	{
		fprintf(stderr,"keys.c: Begin Transaction Failed.\n");

		return -1;
	}

	result = insert_key_into_db(conn,pubkey,source);
	if(result == -1)
	{
		fprintf(stderr,"keys.c: add_key_to_db:  insert key into db returned -1.");

		return -1;
	}

	if(db_commit_transaction(conn) == -1)
	{
		fprintf(stderr,"Commit Transaction Failed.\n");

		return -1;
	}


	return result;
}


int add_with_delete_key(PGconn *conn,struct openPGP_pubkey *key_result,int source)
{
	int result = 0;

	if((conn == NULL) || (key_result == NULL))
	{
		fprintf(stderr,"add_with_delete_key passed null arg.\n");

		return -1;
	}

	if(db_begin_transaction(conn) == -1)
	{
		fprintf(stderr,"Begin Transaction Failed.\n");

		return -1;
	}

	result = delete_key_from_db(conn,key_result->fp_db,0);
	if(result == -1)
	{
		return -1;
	}

	result = insert_key_into_db(conn,key_result,source);
	if(result == -1)
	{
		return -1;
	}

	if(db_commit_transaction(conn) == -1)
	{
		fprintf(stderr,"keys.c: Commit Transaction Failed.\n");

		return -1;
	}


	return result;
}


int insert_key_into_db(PGconn *conn,struct openPGP_pubkey *key_result,int source)
{
	struct user_id  *uid_walk = NULL;

	int             did_primary = 0;
	char            stmt[401];
	Oid             the_key = 0;
	int             the_key_fd = 0;
	int             status_flag = 0;

	long            len = 0;

	int             result = 0;


	if((conn == NULL) || (key_result == NULL))
	{
		fprintf(stderr,"insert_key_into_db passed null arg.\n");

		return -1;
	}

	memset(stmt,0x00,401);

	the_key = lo_creat(conn,INV_READ|INV_WRITE);
	if(the_key == 0)
	{
		do_error_page("keys.c: can't create large object\n");

		return -1;
	}

	/******** Begin lo data write ******************************************/
	the_key_fd = lo_open(conn, the_key, INV_WRITE);
	/* TODO: Make sure lo_open worked. */

	if(key_result->radix_data == NULL)
	{
		fprintf(stderr,"keys.c:  Radix data is null.  Fatal Error.\n");
		return -1;
	}
	len = strlen(key_result->radix_data);

	status_flag = lo_write(conn,the_key_fd,&(key_result->radix_data[0]),len);

	if(status_flag < 1)
	{
		fprintf(stderr,"We Failed: Radix data write\n");

		return -1;
	}

	lo_close(conn,the_key_fd);
	/********* End lo data write ********************************************/

	snprintf(stmt,400,"insert into cks_fp_key_table values('%s','%s','%d')",key_result->fp_db,key_result->encoded_cksum,the_key);

	result = db_stmt(conn,stmt,NULL);
	if(result == -1)
	{
		/* TODO: Error message. */

		return -1;
	}

	snprintf(stmt,400,"insert into cks_keyid_table values('%s','%s','%s')",key_result->keyid_t,key_result->fkeyid_t,key_result->fp_db);

	result = db_stmt(conn,stmt,NULL);
	if(result == -1)
	{
		return -1;
	}

	snprintf(stmt,400,"insert into cks_key_info_table values('%s','%s','%d','%d','%d','%ld','%ld','%d')",key_result->fp_db,key_result->keyid_t,key_result->key_version,key_result->algo_id,key_result->key_size,key_result->creation_time,key_result->expiration_time,key_result->key_revoked);

	result = db_stmt(conn,stmt,NULL);
	if(result == -1)
	{
		return -1;
	}

	uid_walk = (struct user_id *)get_first_uid(key_result->ids);
	/* TODO: Check result */
	while(uid_walk != NULL)
	{
		if(did_primary == 0)
		{
			snprintf(stmt,400,"insert into cks_puid_table values('%s','%s','%s')",key_result->fkeyid_t,key_result->fp_db,uid_walk->id_data);

			result = db_stmt(conn,stmt,NULL);
			if(result == -1)
			{
				return -1;
			}

			snprintf(stmt,400,"insert into cks_uid_table values('%s','1','%s','%s')",key_result->fkeyid_t,key_result->fp_db,uid_walk->id_data);

			did_primary = 1;
		}
		else
		{
			snprintf(stmt,400,"insert into cks_uid_table values('%s','0','%s','%s')",key_result->fkeyid_t,key_result->fp_db,uid_walk->id_data);
		}

		result = db_stmt(conn,stmt,NULL);
		if(result == -1)
		{
			return -1;
		}

		uid_walk = uid_walk->next;
	}

	if(source != D_SOURCE_MAIL_SYNC)
	{
		/* This is temporary until I finish the sync code.  This keeps keys that come in from
		   pgp.net from being put in the sync table, so that I know I shouldn't send them back
		   to pgp.net.  I need to come up with a good table structure for cks_pending_sync
		   that tracks which servers need to get a key and which have already seen it.  I've
		   been dragging my feet onthis, because I've been thinking about just doing it
		   real time.  I still don't know what I'm going to do with this.  Once someone else
		   joins the cryptnet keyserver network, I'll have some pressure to resolve it
		   which might actually motivate me to get it done instead of just writing comments
		   that are way to long. :)
		*/

		snprintf(stmt,400,"insert into cks_pending_sync values('%s')",key_result->fp_db);
		result = db_stmt(conn,stmt,NULL);
		if(result == -1)
		{
			return -1;
		}
	}

	return 0;
}

int delete_key_from_db(PGconn *conn,char *fp,int trans_flag)
{
	int     result = 0;
	char    stmt[401];


	if((conn == NULL) || (fp == NULL))
	{
		fprintf(stderr,"delete_key_from_db passed null arg.\n");

		return -1;
	}

	memset(stmt,0x00,401);

	if(trans_flag == 1)
	{
		if(db_begin_transaction(conn) == -1)
		{
			fprintf(stderr, "Failed to begin transaction.\n");

			return -1;
		}
	}

	snprintf(stmt,400, "delete from cks_keyid_table where fp='%s'",fp);
	result = db_stmt(conn,stmt,NULL);
	if(result == -1)
	{
		fprintf(stderr,"db_stmt failed.\n");

		return -1;
	}
	snprintf(stmt,400, "delete from cks_key_info_table where fp='%s'",fp);
	result = db_stmt(conn,stmt,NULL);
	if(result == -1)
	{
		fprintf(stderr,"db_stmt failed.\n");

		return -1;
	}
	snprintf(stmt,400, "delete from cks_fp_key_table where fp='%s'",fp);
	result = db_stmt(conn,stmt,NULL);
	if(result == -1)
	{
		fprintf(stderr,"db_stmt failed.\n");

		return -1;
	}
	snprintf(stmt,400, "delete from cks_uid_table where fp='%s'",fp);
	result = db_stmt(conn,stmt,NULL);
	if(result == -1)
	{
		fprintf(stderr,"db_stmt failed.\n");

		return -1;
	}
	snprintf(stmt,400, "delete from cks_puid_table where fp='%s'",fp);
	result = db_stmt(conn,stmt,NULL);
	if(result == -1)
	{
		fprintf(stderr,"db_stmt failed.\n");

		return -1;
	}

	snprintf(stmt,400, "delete from cks_pending_sync where fp='%s'",fp);
	/* No need to check result.  There may or may not be a record in
		cks_pending_sync */
	db_stmt(conn,stmt,NULL);

	if(trans_flag == 1)
	{
		if(db_commit_transaction(conn) == -1)
		{
			fprintf(stderr, "Failed to commit transaction.\n");

			return -1;
		}
	}

	return result;
}


int purge_corrupt_key_from_db(PGconn *conn,char *fp,int source_flag)
{
	int result = 0;

	if(conn != NULL)
	{
		if(validate_fingerprint(fp) != -1)
		{
			if(key_exists(conn,fp))
			{
				result = delete_key_from_db(conn,fp,1);
			}
		}
		else
		{
			fprintf(stderr,"purge_corrupt_key_from_db passed invalid fingerprint.\n");

			return -1;
			}
		}
		else
        {
			fprintf(stderr,"purge_corrupt_key_from_db passed null arg.\n");

			return -1;
		}


	return result;
}


int retry_key_addition_after_purge(PGconn *conn,struct openPGP_pubkey *pubkey)
{
	/* The idea here is that if we error on an insert and subsequetly purge
	   a key thought to be bad from the db, we should make one additional
	   attempt to insert the key into the database. */


	return 0;
}


int build_new_binary_buffer(struct openPGP_pubkey **pubkey)
{
	/* I'm pretty sure this just needs to be deleted as it's handled in merge.c */


	return 0;
}


int print_sig_data(char *str)
{
	char *p = NULL;
	char *orig = NULL;
	char *s = NULL;
	unsigned int str_len = 0;
	unsigned int max_len = 0;


	if(str == NULL)
	{
		return -1;
	}
	str_len = strlen(str);
	max_len = str_len * 2 + 1;
	orig = (char *)malloc(max_len+1);
	if(orig == NULL)
	{
		fprintf(stderr, "keys.c:  malloc call failed: memory allocation erorr\n");

		return -1;
	}
	memset(orig,'\0',max_len+1);
	p = &orig[0];
	s = &str[0];

	while(*s)
	{
		if(*s == '<')
		{
			str_len = str_len + 4;
			if(str_len > max_len)
			{
				printf("Rejected UID.  Max length exceeded.\n");
				if(orig != NULL)
					free(orig);

				return -1;
			}
			*s++;
			*p++ = '&';
			*p++ = 'l';
			*p++ = 't';
			*p++ = ';';
		}
		else if(*s == '>')
		{
			str_len = str_len + 4;
			if(str_len > max_len)
			{
				printf("Rejected UID. Max length exceeded.\n");
				if(orig != NULL)
					free(orig);

				return -1;
			}
			*s++;
			*p++ = '&';
			*p++ = 'g';
			*p++ = 't';
			*p++ = ';';
		}
		else if(*s == '\0')
			break;

		*p = *s;
		if(*s == '\0')
			break;
		*s++;
		*p++;
	}
	*p++ = '\0';
	printf("%s",orig);

	if(orig != NULL)
		free(orig);


	return 0;
}


int print_uid(PGconn *conn,unsigned char *keyid, unsigned char *full_keyid)
{
	PGresult	*result = NULL;
	char		keyid_query[301];
	char		*buffer = NULL;
	int			tmp_val = 0;


	if((conn == NULL) || (keyid == NULL) || (full_keyid == NULL))
	{
		fprintf(stderr,"print_uid was pass a null arg.\n");

		return -1;
	}

	/*
		We search for a 4 byte keyid here instead of an 8 byte one because you can generate v4
		sigs with a v3 key and RFC2440 does not include a mechanism for encluding the key version
		with the signature.  So how can we know if a key is a v4 key with a 8byte id or a v3 key
		with no 8 byte id?  We can't so we just have to query with a 4byte keyid.
	*/
	if( (memcmp(keyid,"00000000",8) == 0) || (memcmp(full_keyid,"0000000000000000",16) == 0) )
	{
		printf("<li><a href=\"search.cgi?stype=keyid_4b&keyid_4b=%s\">0x%s</a> (Missing Key ID Packet)</li>",keyid,keyid);

		return 0;
	}
/*
	snprintf(keyid_query,1023,"select cks_uid_table.fkey_id,p_uid,cks_uid_table.fp,uid from cks_uid_table, cks_keyid_table where p_uid = 1 and cks_uid_table.fkey_id = rtrim(cks_keyid_table.fkey_id) and cks_keyid_table.key_id='%s'", keyid);
*/
	memset(keyid_query,0x00,301);
	snprintf(keyid_query,300,"select uid from cks_puid_table where fkeyid='%s'",full_keyid);
	result = PQexec(conn, keyid_query);
	if((PQresultStatus(result) != PGRES_TUPLES_OK) && (PQresultStatus(result) != PGRES_COMMAND_OK))
	{
		fprintf(stderr,"PQERROR keys 1079: %s\n",PQresultErrorMessage(result));
		fprintf(stderr,"PQSTATUS keys 1080: %d\n",PQresultStatus(result));
		do_error_page("keyid_query: Bad Tuples.");
		fprintf(stderr,"keys.c:  keyid_query returned Bad Tuples.\n");
		fprintf(stderr,"keys.c:  Offending SQL: %s\n",keyid_query);
		PQclear(result);
		db_disconnect(conn);

		return -1;
	}
	if(PQntuples(result) != 0)
	{
		printf("<li><a href=\"search.cgi?stype=keyid_4b&keyid_4b=%s\">0x%s</a> ",keyid,keyid);
		tmp_val = strlen(PQgetvalue(result,0,0));
		buffer = (char *)malloc(tmp_val+2);
		if(buffer == NULL)
		{
			fprintf(stderr,"Out of memory. Malloc Call Failed.\n");
			PQclear(result);

			return -1;
		}
		strncpy(buffer,PQgetvalue(result,0,0),tmp_val+1);
		print_sig_data(buffer);
		if(buffer != NULL)
		{
			free(buffer);
		}
		printf("</li>\n");
	}
	else
	{
		/* I hate pgp v3 stuff */
		PQclear(result);
		snprintf(keyid_query,300,"select uid from cks_puid_table where fkeyid='%s'",keyid);
		result = PQexec(conn, keyid_query);
		if((PQresultStatus(result) != PGRES_TUPLES_OK) && (PQresultStatus(result) != PGRES_COMMAND_OK))
		{
			do_error_page("keyid_query: Bad Tuples.");
			fprintf(stderr,"keys.c:  keyid_query returned Bad Tuples.\n");
			fprintf(stderr,"keys.c:  Offending SQL: %s\n",keyid_query);
			PQclear(result);

			return -1;
		}
		if(PQntuples(result) != 0)
		{
			printf("<li><a href=\"search.cgi?stype=keyid_4b&keyid_4b=%s\">0x%s</a> ",keyid,keyid);
			tmp_val = strlen(PQgetvalue(result,0,0));
			buffer = (char *)malloc(tmp_val+2);
			if(buffer == NULL)
			{
				fprintf(stderr,"Out of memory. Malloc Call Failed.\n");
				PQclear(result);

				return -1;
			}
			strncpy(buffer,PQgetvalue(result,0,0),tmp_val+1);
			print_sig_data(buffer);
			if(buffer != NULL)
			{
				free(buffer);
			}
		}
		else
		{
			printf("<li><a href=\"search.cgi?stype=keyid_4b&keyid_4b=%s\">0x%s</a> (Unknown Signer)</li>\n",keyid,keyid);
		}
	}

	PQclear(result);


	return 0;
}


int print_fp(unsigned char *fp)
{
	unsigned int len = 0;


	if(fp == NULL)
	{
		fprintf(stderr,"print_fp was passed a null arg.\n");

		return -1;
	}

	len = strlen(fp);

	if(len == 40)
	{
		printf("%c%c%c%c %c%c%c%c %c%c%c%c %c%c%c%c %c%c%c%c&nbsp;&nbsp;%c%c%c%c %c%c%c%c %c%c%c%c %c%c%c%c %c%c%c%c",fp[0],
			fp[1],fp[2],fp[3],fp[4],fp[5],fp[6],fp[7],fp[8],fp[9],fp[10],fp[11],fp[12],fp[13],fp[14],fp[15],fp[16],fp[17],fp[18],
			fp[19],fp[20],fp[21],fp[22],fp[23],fp[24],fp[25],fp[26],fp[27],fp[28],fp[29],fp[30],fp[31],fp[32],fp[33],fp[34],
			fp[35],fp[36],fp[37],fp[38],fp[39]);
	}
	else if(len == 32)
	{
		printf("%c%c %c%c %c%c %c%c %c%c %c%c %c%c %c%c&nbsp;&nbsp;%c%c %c%c %c%c %c%c %c%c %c%c %c%c %c%c",fp[0],fp[1],fp[2],
			fp[3],fp[4],fp[5],fp[6],fp[7],fp[8],fp[9],fp[10],fp[11],fp[12],fp[13],fp[14],fp[15],fp[16],fp[17],fp[18],fp[19],fp[20],
			fp[21],fp[22],fp[23],fp[24],fp[25],fp[26],fp[27],fp[28],fp[29],fp[30],fp[31]);
	}
	else
	{
		fprintf(stderr,"keys.c:  Key with bad fingerprint detected: %s\n",fp);

		return -1;
	}


	return 0;
}


int mail_pubkey(struct openPGP_pubkey *pubkey,struct cks_config *config, struct servers_to_sync *sunk_servers,
			struct servers_to_sync *servers)
{
	/* The idea here was that we could immediatly send out a sync mail when a new key came in
	   rather than running a cron job.  I'm not sure what I'm going to do here.  I could go
	   either way. */

	return 0;
}


int echo_radix_key(struct openPGP_pubkey *key_result,struct cks_config *config)
{
	unsigned long len = 0;
	unsigned int i = 0;
	unsigned int j = 1;


	if((key_result == NULL) || (config == NULL))
	{
		fprintf(stderr,"keys.c: echo_radix_key was passed a null arg.\n");

		return -1;
	}

	printf("<hr size=\"1\" width=\"100%%\">\n");
	printf("<pre>\n");
	printf("-----BEGIN PGP PUBLIC KEY BLOCK-----\n");
	printf("%s",config->vrsn);
	printf("%s",config->cmnt);
	len = strlen(key_result->radix_data);
	if(len == 0)
	{
		fprintf(stderr,_("Error Detected: Unable to echo radix key. Key returns radix length of 0.\n"));

		return -1;
	}
	else
	{
		for(i=0;i<len;i++)
		{
			printf("%c",key_result->radix_data[i]);
			if(j == 64)
			printf("\n");
			else if((j % 64) == 0) printf("\n");
				j++;
		}
		if((j % 64) != 1)
			printf("\n");
		printf("=%s\n",key_result->encoded_cksum);
	}
	printf("-----END PGP PUBLIC KEY BLOCK-----\n");
	printf("</pre>\n");


	return 0;
}


int strtoupper(char *string)
{
	unsigned int i = 0;


	if(string == NULL)
	{
		fprintf(stderr,"strtoupper was passed a null arg.\n");

		return -1;
	}
	while (string[i])
	{
		string[i] = toupper(string[i]);
		i++;
	}

	return 0;
}

int remove_spaces(char *data)
{
	unsigned int i = 0;
	unsigned int j = 0;


	if(data == NULL)
	{
		fprintf(stderr,"remove_spaces was passed a null arg.\n");

		return -1;
	}
	while(data[j])
	{
		if(isspace(data[j]))
			j++;
		else
			data[i++] = toupper(data[j++]);
	}
	data[i] = '\0';

	return 0;
}

int decode_radix(struct openPGP_pubkey *pubkey)
{
	int rslt = 0;
	long buffer_length = 0;

	if(pubkey == NULL)
	{
		fprintf(stderr,"decode_radix was passed a null arg.\n");

		return -1;
	}
	if(pubkey->buffer != NULL)
	{
		free(pubkey->buffer);
	}

	buffer_length = strlen(pubkey->radix_data) * 2;
	pubkey->buffer = (unsigned char *)malloc(buffer_length);
	if(pubkey->buffer == NULL)
	{
		fprintf(stderr,_("cks_export.c:  Malloc call failed: out of memory!\n"));
		pubkey->key_status = -1;

		return -1;
	}
	memset(pubkey->buffer,0x00,buffer_length);
	pubkey->buffer_idx = decode_buffer(pubkey->radix_data,pubkey->buffer);
	if(pubkey->buffer_idx == 0)
	{
		fprintf(stderr,_("cks_export.c:  error null buffer decoded length is 0.\n"));
		pubkey->key_status = -1;

		return -1;
	}

	return rslt;
}

int remove_key_from_sync_list(PGconn *conn, unsigned char *fp, FILE *err_log)
{
	unsigned char delete_stmt[200];
	int result = 0;

	if((conn == NULL) || (fp == NULL))
	{
		fprintf(stderr,"remove_key_from_sync_list was passed a null arg.\n");

		return -1;
	}

	memset(delete_stmt,0x00,200);

	snprintf(delete_stmt,199,"delete from cks_pending_sync where fp='%s'",fp);

	result = db_stmt(conn,delete_stmt,NULL);
	if(result == -1)
	{
		fprintf(err_log, _("cks_sync:  Non-Fatal Error.\n"));
		fprintf(err_log, _("cks_sync:  Failed to delete key with fingerprint '%s'\n"),fp);
		fprintf(err_log, _("cks_sync:  from cks_pending_sync table.\n"));
		fflush(err_log);
	}

	return result;
}

int validate_fingerprint(unsigned char *fp)
{
 	int tmp_strlen = 0;
	

	if(fp == NULL)
	{
		return -1;
	}
	if( (tmp_strlen != 40) || (tmp_strlen != 32) )
	{
		return -1;
	}

	return 0;
}
