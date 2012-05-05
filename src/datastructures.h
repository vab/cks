/* datastructures.h - Generic Datastructures header file
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

#ifndef DATASTRUCTURES
#define DATASTRUCTURES

#include <stdio.h>
#include <stdlib.h>

#include "cgi.h"
#include "cks_constants.h"


struct openPGP_keyring
{
	struct openPGP_pubkey *pubkeys;
	unsigned char *buffer;
	unsigned long buffer_idx;
	unsigned char *radix_data;
	unsigned char encoded_cksum[5];
};

struct openPGP_pubkey
{
	int key_status;
	unsigned char key_version;
	unsigned int  key_revoked;
	unsigned char revoked_reason;
	unsigned int  algo_id;
	unsigned char algo[4];
	unsigned char keyid[8];
	unsigned char keyid_t[9];
	unsigned char fkeyid_t[17];
	unsigned char fp[20];
	unsigned char fp_t[61];
	unsigned char fp_db[41];
	unsigned char size[5];
	/* special data is 0x99 +2 needed for gening fp of subkeys */
	unsigned char special_data[3];
	unsigned int  key_size;
	long creation_time;
	long expiration_time;
	struct user_id *ids;
	struct openPGP_subkey *subkeys;
	/* This is all old openPGP_pubkey stuff */
	unsigned char *buffer;
	unsigned char *radix_data;
	unsigned char *radix_key;
	unsigned long buffer_idx;
	unsigned char encoded_cksum[5];
	struct openPGP_packet *the_packet;
	struct openPGP_packet *packet_list;
	int keyserver_no_modify;
	int has_photo;
	unsigned char *img_data;
	unsigned long image_len;

	struct openPGP_pubkey *prev;
	struct openPGP_pubkey *next;
};

struct user_id
{
	unsigned long packet_length;
	unsigned char *packet_data;
	unsigned char *id_data;
	unsigned int id_len;
	unsigned int revoked;

	struct user_id *prev;
	struct user_id *next;
	struct key_signature *signatures;
	struct openPGP_packet *the_packet;
};

struct key_signature
{
	unsigned char sig_version;
	unsigned char sig_type;
	unsigned char key_id[8];
	unsigned int  lkeyid;
	unsigned int  creation_time;

	struct key_signature *prev;
	struct key_signature *next;
	struct openPGP_packet *the_packet;
};

struct openPGP_subkey
{
	unsigned char subkey_version;
	unsigned int  algo_id;
	unsigned char algo[4];
	unsigned char keyid[8];
	unsigned char keyid_t[9];
	unsigned char fp[20];
	long creation_time;
	long expiration_time;
	unsigned int  key_size;

	struct key_signature *binding_signatures;
	struct openPGP_subkey *prev;
	struct openPGP_subkey *next;
	struct openPGP_packet *the_packet;
};

struct openPGP_packet
{
	int packet_id;
	unsigned long len_bytes;
	unsigned char pkt_len_d[2];
	unsigned char the_len_bytes[5];
	unsigned long packet_length;
	unsigned char *packet_data;
	unsigned long full_packet_length;
	unsigned char *full_packet_data;
	unsigned int  header_length;

	struct openPGP_packet *prev;
	struct openPGP_packet *next;
};

struct openPGP_subpacket
{
	int subpacket_id;
	unsigned long len_bytes;
	unsigned long subpacket_length;
	unsigned char *subpacket_data;

	struct openPGP_subpacket *prev;
	struct openPGP_subpacket *next;
};

struct openPGP_attribute
{
	unsigned char *attr_data;
	struct openPGP_packet *the_packet;
};

struct cks_config
{
	unsigned char bind_ip[16];
	unsigned char bind_port[10];
	int db_type;
	unsigned char dbsrvr_ip[16];
	unsigned char dbsrvr_port[10];
	unsigned char dbsrvr_db[16];
	int use_cmnt;
	unsigned char vrsn[101];
	unsigned char cmnt[201];
	unsigned char adm_email[101];
	unsigned char sync_email[101];
	/* Accept Version 2 Keys */
	int acpt_v2;
	/* Accept Version 3 Keys */
	int acpt_v3;
	/* Maximum Number Of Key To Return */
	int max_ret;
	/* Max keys to return per ID */
	int key_ret;
	/* Max keys w/ duplicate ID to accept */
	int dup_acpt;
	/* Display Link To Search BigLumber */
	int biglumber;
	/* Attempt Off Network Fetch */
	int aonf;
	unsigned char err_log[201];
	unsigned char mail_err_log[201];
	unsigned char data_log[201];

	struct d_linked_list *cache;
};

struct linked_list
{
	char *data;

	struct linked_list *next;
};

struct d_linked_list
{
	void *name;
	void *value;
	void *keyid;
	void *lkeyid;

	struct d_linked_list *prev;
	struct d_linked_list *next;
};

struct name_value_pair_dllst
{
	unsigned char *name;
	unsigned char *value;

	struct name_value_pair_dllst *prev;
	struct name_value_pair_dllst *next;
};

struct keys_to_sync
{
	unsigned char fp[41];

	struct keys_to_sync *next;
};

struct servers_to_sync
{
	unsigned char srvr[301];
	unsigned char email[301];

	struct servers_to_sync *prev;
	struct servers_to_sync *next;
};


int init_openPGP_keyring(struct openPGP_keyring **,long);
int init_openPGP_pubkey(struct openPGP_pubkey **,long);
int init_user_id(struct user_id *);
int init_key_signature(struct key_signature *);
int init_openPGP_subkey(struct openPGP_subkey *);
int init_openPGP_packet(struct openPGP_packet **);
int init_openPGP_subpacket(struct openPGP_subpacket *);

struct openPGP_packet *get_first_packet(struct openPGP_packet *);
struct openPGP_packet *get_last_packet(struct openPGP_packet *);
struct openPGP_subpacket *get_first_subpacket(struct openPGP_packet *);
struct openPGP_subpacket *get_last_subpacket(struct openPGP_packet *);
struct openPGP_pubkey *get_first_pubkey(struct openPGP_pubkey *);
struct openPGP_pubkey *get_last_pubkey(struct openPGP_pubkey *);
struct user_id *get_first_uid(struct user_id *);
struct user_id *get_last_uid(struct user_id *);
struct key_signature *get_first_sig(struct key_signature *);
struct key_signature *get_last_sig(struct key_signature *);
struct openPGP_subkey *get_first_subkey(struct openPGP_subkey *);
struct openPGP_subkey *get_last_subkey(struct openPGP_subkey *);

int add_packet(struct openPGP_pubkey **, struct openPGP_packet *);
int add_pubkey(struct openPGP_keyring *, struct openPGP_pubkey *);
int add_subkey(struct openPGP_pubkey *, struct openPGP_subkey *);
int add_uid(struct openPGP_pubkey *, struct user_id *);
int add_sig(struct user_id *, struct key_signature *);
int add_subkey_binding_sig(struct openPGP_subkey *, struct key_signature *);

int extract_uid(struct user_id *);
int extract_sig(struct key_signature *);
int extract_subkey(struct openPGP_subkey *);
struct servers_to_sync * extract_srvr(struct servers_to_sync *);

int init_srvr_to_sync(struct servers_to_sync *);
struct servers_to_sync * add_server(struct servers_to_sync *, struct servers_to_sync *);
struct servers_to_sync * get_first_server(struct servers_to_sync *);
struct servers_to_sync * get_last_server(struct servers_to_sync *);
int count_servers_to_sync(struct servers_to_sync *);

/* d_linked_list */
struct d_linked_list * new_dll_node(void *, unsigned long, void *, unsigned long);
int add_dll_item(struct d_linked_list **, struct d_linked_list *);
struct d_linked_list * get_first_dll_node(struct d_linked_list *);
struct d_linked_list * get_last_dll_node(struct d_linked_list *);
void free_dll(struct d_linked_list **);
/* /d_linked_list */

struct name_value_pair_dllst *get_first_pair(struct name_value_pair_dllst *);
struct name_value_pair_dllst *get_last_pair(struct name_value_pair_dllst *);
char *get_value(struct name_value_pair_dllst *,char *);

void free_servers_to_sync(struct servers_to_sync **);
void free_name_value_pair_dllst(struct name_value_pair_dllst **);
void free_keyring(struct openPGP_keyring **);
void free_pubkey(struct openPGP_pubkey **);
void free_pubkey_debug(struct openPGP_pubkey **);
void free_packet(struct openPGP_packet **);

/*
#define DEBUG
*/
#endif
