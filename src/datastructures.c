/* datastructures.c - Generic Datastructures functions file
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

#include "datastructures.h"


int init_openPGP_keyring(struct openPGP_keyring **keyring,long buff_size)
{
	if(buff_size == 0)
		buff_size = 128000;

	(*keyring)->pubkeys = NULL;
	(*keyring)->buffer_idx = 0;
	memset((*keyring)->encoded_cksum,0x00,5);
	if(NULL == ((*keyring)->buffer = (char *)malloc(buff_size)))
	{
		return -1;
	}
	memset((*keyring)->buffer,0x00,buff_size);
	if(NULL == ((*keyring)->radix_data = (char *)malloc(buff_size)))
	{
		return -1;
 	}
	memset((*keyring)->radix_data,0x00,buff_size);

	return 0;
}

int init_openPGP_pubkey(struct openPGP_pubkey **the_key,long buff_size)
{
	if(buff_size == 0)
		buff_size = 128000;

	(*the_key)->key_version = 0;
        (*the_key)->key_revoked = 0;
	(*the_key)->revoked_reason = 0x00;
        (*the_key)->algo_id = 0;
        memset((*the_key)->algo,0x00,4);
        memset((*the_key)->keyid,0x00,8);
        memset((*the_key)->keyid_t,0x00,9);
        memset((*the_key)->fkeyid_t,0x00,17);
        memset((*the_key)->fp,0x00,20);
        memset((*the_key)->fp_t,0x00,61);
        memset((*the_key)->fp_db,0x00,41);
        memset((*the_key)->size,0x00,5);
        memset((*the_key)->special_data,0x00,3);
        (*the_key)->key_size = 0;
        (*the_key)->creation_time = 0;
        (*the_key)->expiration_time = 0;
	(*the_key)->buffer_idx = 0;
        memset((*the_key)->encoded_cksum,0x00,5);
	(*the_key)->radix_key = NULL;
	(*the_key)->radix_data = NULL;
	(*the_key)->buffer = NULL;
	(*the_key)->keyserver_no_modify = 0;
	(*the_key)->has_photo = 0;
	(*the_key)->img_data = NULL;
	(*the_key)->image_len = 0;

        (*the_key)->subkeys = NULL;
        (*the_key)->ids = NULL;
        (*the_key)->the_packet = NULL;
        (*the_key)->packet_list = NULL;

        (*the_key)->prev = NULL;
        (*the_key)->next = NULL;

        if(NULL == ((*the_key)->buffer = (char *)malloc(buff_size)))
        {
        	return -1;
        }
        if(NULL == ((*the_key)->radix_data = (char *)malloc(buff_size)))
        {
		return -1;
        }
	memset((*the_key)->buffer,0x00,buff_size);
	memset((*the_key)->radix_data,0x00,buff_size);


	return 0;
}

int init_user_id(struct user_id *the_userid)
{
	the_userid->packet_length = 0;
	the_userid->packet_data = NULL;
	the_userid->id_data = NULL;
	the_userid->id_len = 0;
	the_userid->revoked = 0;
	the_userid->signatures = NULL;
	the_userid->the_packet = NULL;

	the_userid->prev = NULL;
	the_userid->next = NULL;

	return 0;
}

int init_key_signature(struct key_signature *the_signature)
{
	the_signature->sig_version = 0;
	the_signature->sig_type = 0;
	memset(the_signature->key_id,0x00,8);
	the_signature->lkeyid = 0;
	the_signature->creation_time = 0;
	the_signature->the_packet = NULL;

	the_signature->prev = NULL;
	the_signature->next = NULL;

	return 0;
}

int init_openPGP_subkey(struct openPGP_subkey *the_subkey)
{
	the_subkey->subkey_version = 0;
	the_subkey->algo_id = 0;
	memset(the_subkey->algo,0x00,4);
	memset(the_subkey->keyid,0x00,8);
	memset(the_subkey->fp,0x00,20);
	the_subkey->creation_time = 0;
	the_subkey->expiration_time = 0;
	the_subkey->binding_signatures = NULL;
	the_subkey->the_packet = NULL;

	the_subkey->prev = NULL;
	the_subkey->next = NULL;

	return 0;
}

int init_openPGP_packet(struct openPGP_packet **the_packet)
{
	(*the_packet)->packet_id = 0;
	(*the_packet)->len_bytes = 0;
	memset((*the_packet)->pkt_len_d,0x00,2);
	memset((*the_packet)->the_len_bytes,0x00,5);
	(*the_packet)->packet_length = 0;
	(*the_packet)->packet_data = NULL;
	(*the_packet)->full_packet_length = 0;
	(*the_packet)->full_packet_data = NULL;
	(*the_packet)->header_length = 0;

	(*the_packet)->prev = NULL;
	(*the_packet)->next = NULL;

	return 0;
}

int init_openPGP_subpacket(struct openPGP_subpacket *the_subpacket)
{
	the_subpacket->subpacket_id = 0;
	the_subpacket->len_bytes = 0;
	the_subpacket->subpacket_length = 0;
	the_subpacket->subpacket_data = NULL;

	the_subpacket->prev = NULL;
	the_subpacket->next = NULL;

	return 0;
}

int init_srvr_to_sync(struct servers_to_sync *new_srvr)
{
	memset(new_srvr->srvr,0x00,301);
	memset(new_srvr->email,0x00,301);

	new_srvr->prev = NULL;
	new_srvr->next = NULL;
	
	return 0;
}

int add_pubkey(struct openPGP_keyring *the_keyring, struct openPGP_pubkey *new_pubkey)
{
	struct openPGP_pubkey *last_pubkey;

        last_pubkey = (struct openPGP_pubkey *)get_last_pubkey(the_keyring->pubkeys);
        if(last_pubkey == NULL)
        {
		the_keyring->pubkeys = new_pubkey;
                new_pubkey->prev = NULL;
                new_pubkey->next = NULL;
        }
        else
        {
		last_pubkey->next = new_pubkey;
                new_pubkey->prev = last_pubkey;
                new_pubkey->next = NULL;
                the_keyring->pubkeys = new_pubkey;
        }

	return 0;
}

int add_subkey(struct openPGP_pubkey *the_key, struct openPGP_subkey *new_subkey)
{
        struct openPGP_subkey *last_subkey;

        last_subkey = (struct openPGP_subkey *)get_last_subkey(the_key->subkeys);
        if(last_subkey == NULL)
        {
                the_key->subkeys = new_subkey;
                new_subkey->prev = NULL;
                new_subkey->next = NULL;
                new_subkey->binding_signatures = NULL;
        }
        else
        {
                last_subkey->next = new_subkey;
                new_subkey->prev = last_subkey;
                new_subkey->next = NULL;
                new_subkey->binding_signatures = NULL;
                the_key->subkeys = new_subkey;
        }

	return 0;
}

struct openPGP_pubkey *get_first_pubkey(struct openPGP_pubkey *pubkeys)
{
	if(pubkeys != NULL)
        {
		while(pubkeys->prev != NULL)
                {
			pubkeys = pubkeys->prev;
                }
        }
	return pubkeys;
}

struct openPGP_pubkey *get_last_pubkey(struct openPGP_pubkey *pubkeys)
{
        if(pubkeys != NULL)
        {
                while(pubkeys->next != NULL)
                {
                        pubkeys = pubkeys->next;
                }
        }
        return pubkeys;
}

struct openPGP_subkey *get_first_subkey(struct openPGP_subkey *subkeys)
{
        if(subkeys != NULL)
        {
                while(subkeys->prev != NULL)
                {
                        subkeys = subkeys->prev;
                }
        }
        return subkeys;
}

struct openPGP_subkey *get_last_subkey(struct openPGP_subkey *subkeys)
{
        if(subkeys != NULL)
        {
                while(subkeys->next != NULL)
                {
                        subkeys = subkeys->next;
                }
        }
        return subkeys;
}

int add_packet(struct openPGP_pubkey **the_key, struct openPGP_packet *new_packet)
{
        struct openPGP_packet *last_packet = NULL;
/*
	fprintf(stderr,"Adding Packet: ID: %d Len: %d\n",new_packet->packet_id,new_packet->len_bytes);
*/

	if(the_key == NULL)
	{
		fprintf(stderr,"datastructures.c: add_packet: the_key was NULL.\n");

		return -1;
	}
	if(new_packet == NULL)
	{
		fprintf(stderr,"datastructures.c: add_packet: new_packet was NULL.\n");

		return -1;
	}

        last_packet = (struct openPGP_packet *)get_last_packet((*the_key)->packet_list);
        if(last_packet == NULL)
        {
                (*the_key)->packet_list = new_packet;
                new_packet->prev = NULL;
                new_packet->next = NULL;
        }
        else
        {
                last_packet->next = new_packet;
                new_packet->prev = last_packet;
                new_packet->next = NULL;
                (*the_key)->packet_list = new_packet;
        }
	
	
	return 0;
}

struct openPGP_packet *get_first_packet(struct openPGP_packet *packets)
{
        if(packets != NULL)
        {
                while(packets->prev != NULL)
                {
                        packets = packets->prev;
                }
        }
        return packets;
}

struct openPGP_packet *get_last_packet(struct openPGP_packet *packets)
{
        if(packets != NULL)
        {
		while(packets->next != NULL)
                {
			packets = packets->next;
		}
        }

        return packets;
}

struct openPGP_subpacket *get_first_subpacket(struct openPGP_packet *the_packet)
{

	return NULL;
}

struct openPGP_subpacket *get_last_subpacket(struct openPGP_packet *the_packet)
{

	return NULL;
}

struct user_id *get_first_uid(struct user_id *ids)
{
        if(ids != NULL)
        {
                while(ids->prev != NULL)
                {
                        ids = ids->prev;
                }
        }
        return ids;
}

struct user_id *get_last_uid(struct user_id *ids)
{
        if(ids != NULL)
        {
                while(ids->next != NULL)
                {
                        ids = ids->next;
                }
        }
        return ids;
}

struct key_signature *get_first_sig(struct key_signature *sigs)
{
        if(sigs != NULL)
        {
                while(sigs->prev != NULL)
                {
                        sigs = sigs->prev;
                }
        }
        return sigs;
}

struct key_signature *get_last_sig(struct key_signature *sigs)
{
        if(sigs != NULL)
        {
                while(sigs->next != NULL)
                {
                        sigs = sigs->next;
                }
        }
        return sigs;
}

struct servers_to_sync * get_first_server(struct servers_to_sync *servers)
{
        if(servers != NULL)
        {
                while(servers->prev != NULL)
                {
                        servers = servers->prev;
                }
        }
	return servers;
}

struct servers_to_sync * get_last_server(struct servers_to_sync *servers)
{
	if(servers != NULL)
	{
		while(servers->next != NULL)
		{
			servers = servers->next;
		}
	}
	return servers;
}

int count_servers_to_sync(struct servers_to_sync *srvrs)
{
	int count = 1;
	struct servers_to_sync *walk_srvrs;

	if(srvrs != NULL)
	{
		walk_srvrs = get_first_server(srvrs);
		while(walk_srvrs->next != NULL)
		{
			++count;
			walk_srvrs = walk_srvrs->next;
		}
	}

	return count;
}

int add_uid(struct openPGP_pubkey *the_key, struct user_id *new_id)
{
        struct user_id *last_id;

	if(the_key == NULL) return;
	if(the_key->ids == NULL)
	{
                the_key->ids = new_id;
                new_id->prev = NULL;
                new_id->next = NULL;
                new_id->signatures = NULL;
		return;
	}

        last_id = (struct user_id *)get_last_uid(the_key->ids);
        if(last_id == NULL)
        {
                the_key->ids = new_id;
                new_id->prev = NULL;
                new_id->next = NULL;
                new_id->signatures = NULL;
        }
        else
        {
                last_id->next = new_id;
                new_id->prev = last_id;
                new_id->next = NULL;
                the_key->ids = new_id;
                new_id->signatures =NULL;
        }

	return 0;
}

int add_sig(struct user_id *the_id, struct key_signature *new_sig)
{
        struct key_signature *last_sig;

	if(the_id == NULL) return;

        last_sig = (struct key_signature *)get_last_sig(the_id->signatures);
        if(last_sig == NULL)
        {
                the_id->signatures = new_sig;
                new_sig->prev = NULL;
                new_sig->next = NULL;
        }
        else
        {
                last_sig->next = new_sig;
                new_sig->prev = last_sig;
                new_sig->next = NULL;
                the_id->signatures = new_sig;
        }

	return 0;
}

int add_subkey_binding_sig(struct openPGP_subkey *subkeys, struct key_signature *new_sig)
{
        struct key_signature *subkey_sig;

        if(subkeys == NULL)
        {
		return -1;
        }
        subkey_sig = (struct key_signature *)get_last_sig(subkeys->binding_signatures);
        if(subkey_sig == NULL)
        {
                subkeys->binding_signatures = new_sig;
                new_sig->prev = NULL;
                new_sig->next = NULL;
        }
        else
        {
                subkey_sig->next = new_sig;
                new_sig->prev = subkey_sig;
                new_sig->next = NULL;
                subkeys->binding_signatures = new_sig;
        }

	return 0;
}

struct servers_to_sync * extract_srvr(struct servers_to_sync *srvr)
{

	return srvr;
}

int extract_uid(struct user_id *the_uid)
{
        if(the_uid != NULL)
        {
                if(the_uid->prev != NULL)
                {
                        the_uid->prev->next = the_uid->next;
                }
                if(the_uid->next != NULL)
                {
                        the_uid->next->prev = the_uid->prev;
                }
        }

	return 0;
}

int extract_sig(struct key_signature *the_sig)
{
        if(the_sig != NULL)
        {
                if(the_sig->prev != NULL)
                {
                        the_sig->prev->next = the_sig->next;
                }
                if(the_sig->next != NULL)
                {
                        the_sig->next->prev = the_sig->prev;
                }
        }

	return 0;
}

int extract_subkey(struct openPGP_subkey *the_subkey)
{
	if(the_subkey != NULL)
        {
		if(the_subkey->prev != NULL)
                {
			the_subkey->prev->next = the_subkey->next;
                }
                if(the_subkey->next != NULL)
                {
			the_subkey->next->prev = the_subkey->prev;
                }
        }

	return 0;
}

/*
 * Navigational Code For Data Structures 
 *
 */

struct name_value_pair_dllst *get_first_pair(struct name_value_pair_dllst *the_list)
{
	if(the_list != NULL)
	{
		while(the_list->prev != NULL)
		{
			the_list = the_list->prev;
		}
	}

	return the_list;
}

struct name_value_pair_dllst *get_last_pair(struct name_value_pair_dllst *the_list)
{
	if(the_list != NULL)
	{
		while(the_list->next != NULL)
		{
			the_list = the_list->next;
		}
	}

	return the_list;
}

char *get_value(struct name_value_pair_dllst *the_list,char *name)
{
	if(the_list == NULL)
	{
		return NULL;
	}

	/* Rewind to the beginning */
	the_list = get_first_pair(the_list);

	while(the_list != NULL)
	{
		if(strcmp(the_list->name,name) == 0)
		{
			return the_list->value;
		}
		else
		{
			the_list = the_list->next;
		}
	}

	return NULL;
}

/* d_linked_list */
struct d_linked_list * new_dll_node(void *name, unsigned long name_size, void *value, unsigned long value_size)
{
	struct d_linked_list *new_node;

	new_node = (struct d_linked_list *)malloc(sizeof(struct d_linked_list));
	if(new_node != NULL)
	{
		new_node->next = NULL;
		new_node->prev = NULL;
		new_node->name = NULL;
		new_node->value = NULL;
		new_node->name = malloc(name_size);
		if(new_node->name != NULL)
		{
			memcpy(new_node->name,name,name_size);
		}
		else
		{
			free(new_node);
			new_node = NULL;
		}
		if(value != NULL)
		{
			new_node->value = malloc(value_size);
			if(new_node->value != NULL)
			{
				memcpy(new_node->value,value,value_size);
			}
			else
			{
				free(new_node->name);
				free(new_node);
				new_node = NULL;
			}
		}
	}

	return new_node;
}

int add_dll_item(struct d_linked_list **the_list, struct d_linked_list *new_node)
{
	int rslt = 0;
	struct d_linked_list *local_list;

	if(the_list != NULL)
	{
		local_list = get_last_dll_node(*the_list);
		if(local_list == NULL)
		{
			local_list = new_node;
		}
		else
		{
			local_list->next = new_node;
			new_node->prev = local_list;
		}
		*the_list = local_list;
	}
	else
	{
		rslt = -1;
	}

	return rslt;
}

struct d_linked_list * get_first_dll_node(struct d_linked_list *the_list)
{
	if(the_list != NULL)
	{
		while(the_list->prev != NULL)
		{
			the_list = the_list->prev;
		}
	}

	return the_list;
}

struct d_linked_list * get_last_dll_node(struct d_linked_list *the_list)
{
	if(the_list != NULL)
	{
		while(the_list->next != NULL)
		{
			the_list = the_list->next;
		}
	}

	return the_list;
}

void free_dll(struct d_linked_list **the_list)
{
	struct d_linked_list *walk_list;
	struct d_linked_list *next_node;

	if(the_list != NULL)
	{
		walk_list = get_first_dll_node(*the_list);
		while(walk_list != NULL)
		{
			next_node = walk_list->next;
			if(walk_list->name != NULL)
				free(walk_list->name);
			if(walk_list->value != NULL)
				free(walk_list->value);
			free(walk_list);
			walk_list = next_node;
		}
	}
}
/* /d_linked_list */



void free_servers_to_sync(struct servers_to_sync **srvrs)
{
	struct servers_to_sync *walk_srvr;
	struct servers_to_sync *next_srvr;

	if((*srvrs) != NULL)
	{
		walk_srvr = (struct servers_to_sync *)get_first_server((*srvrs));
		while(walk_srvr != NULL)
		{
			next_srvr = walk_srvr->next;
			free(walk_srvr);
			walk_srvr = next_srvr;
		}
	}
}

void free_name_value_pair_dllst(struct name_value_pair_dllst **the_list)
{
	struct name_value_pair_dllst *walk_pair;
	struct name_value_pair_dllst *next_pair;

	if((*the_list) != NULL)
	{
		walk_pair = (struct name_value_pair_dllst *)get_first_pair((*the_list));
		while(walk_pair != NULL)
		{
			next_pair = walk_pair->next;
			if(walk_pair->name != NULL)
			{
				free(walk_pair->name);
			}
			if(walk_pair->value != NULL)
			{
				free(walk_pair->value);
			}
			free(walk_pair);
			walk_pair = next_pair;
		}
	}

	return;
}



void free_keyring(struct openPGP_keyring **keyring)
{
	struct openPGP_pubkey *walk_pubkey;
        struct openPGP_pubkey *next_pubkey;

	if((*keyring) != NULL)
        {

        	/* Walk the pubkeys and free them. */
        	walk_pubkey = (struct openPGP_pubkey *)get_first_pubkey((*keyring)->pubkeys);
		while(walk_pubkey != NULL)
                {
                	next_pubkey = walk_pubkey->next;
                        free_pubkey(&walk_pubkey);
                        walk_pubkey = next_pubkey;
                }
		if((*keyring)->buffer != NULL)
		{
			free((*keyring)->buffer);
		}
		if((*keyring)->radix_data != NULL);
		{
			free((*keyring)->radix_data);
		}
        	free((*keyring));
        }
}

void free_pubkey(struct openPGP_pubkey **pubkey)
{
        if((*pubkey) != NULL)
        {
                struct user_id          *uid_walk;
                struct user_id          *next_uid;
                struct key_signature    *sig_walk;
                struct key_signature    *next_sig;
                struct openPGP_subkey   *walk_subkey;
                struct openPGP_subkey   *next_subkey;
		struct openPGP_packet	*walk_packet;
		struct openPGP_packet	*next_packet;


		/* Free Buffers */
                if((*pubkey)->buffer != NULL)
                {
                        free((*pubkey)->buffer);
                }
                if((*pubkey)->radix_data != NULL)
                {
                        free((*pubkey)->radix_data);
                }
		if((*pubkey)->radix_key != NULL)
		{
			free((*pubkey)->radix_key);
		}
		if((*pubkey)->img_data != NULL)
		{
			free((*pubkey)->img_data);
		}

                /* Free UID and Signatures */
                uid_walk = (struct user_id *)get_first_uid((*pubkey)->ids);
                while(uid_walk != NULL)
                {
                        next_uid = uid_walk->next;
                        if(uid_walk != NULL)
                        {
                                sig_walk = (struct key_signature *)get_first_sig(uid_walk->signatures);
                                while(sig_walk != NULL)
                                {
                                        next_sig = sig_walk->next;
                                        free(sig_walk);
                                        sig_walk = next_sig;
                                }
                        }
			if(uid_walk->packet_data != NULL)
			{
				free(uid_walk->packet_data);
			}
			if(uid_walk->id_data != NULL)
			{
				free(uid_walk->id_data);
			}
                        free(uid_walk);
                        uid_walk = next_uid;
                }

                /* Free Subkeys and Binding Signatures */
                walk_subkey = (struct openPGP_subkey *)get_first_subkey((*pubkey)->subkeys);
                while(walk_subkey != NULL)
                {
                        next_subkey = walk_subkey->next;
                        sig_walk = (struct key_signature *)get_first_sig(walk_subkey->binding_signatures);
                        while(sig_walk != NULL)
                        {
                        	next_sig = sig_walk->next;
                         	free(sig_walk);
                          	sig_walk = next_sig;
                        }
                        free(walk_subkey);
                        walk_subkey = next_subkey;
                }

		/* Free packets */
		walk_packet = (struct openPGP_packet *)get_first_packet((*pubkey)->packet_list);
		while(walk_packet != NULL)
		{
			next_packet = walk_packet->next;
			free_packet(&walk_packet);
			walk_packet = next_packet;
		}

                /* Free Main Pubkey Datastructure */
                free((*pubkey));
        }
}

void free_pubkey_debug(struct openPGP_pubkey **pubkey)
{
        if(pubkey != NULL)
        {
                struct user_id          *uid_walk;
                struct user_id          *next_uid;
                struct key_signature    *sig_walk;
                struct key_signature    *next_sig;
                struct openPGP_subkey   *walk_subkey;
                struct openPGP_subkey   *next_subkey;


		/* Free Buffers */
                if((*pubkey)->buffer != NULL)
                {
			printf("freeing pubkey->buffer\n");
			fflush(0);
                        free((*pubkey)->buffer);
                }
                if((*pubkey)->radix_data != NULL)
                {
			printf("freeing pubkey->radix_data\n");
			fflush(0);
                        free((*pubkey)->radix_data);
                }
		if((*pubkey)->radix_key != NULL)
		{
			printf("freeing pubkey->radix_key\n");
			fflush(0);
			free((*pubkey)->radix_key);
		}
		if((*pubkey)->the_packet != NULL)
		{
			printf("freeing pubkey->the_packet\n");
			fflush(0);
                	free_packet(&((*pubkey)->the_packet));
		}

                /* Free UID and Signatures */
                uid_walk = (struct user_id *)get_first_uid((*pubkey)->ids);
                while(uid_walk != NULL)
                {
                        next_uid = uid_walk->next;
                        if(next_uid != NULL)
                        {
                                sig_walk = (struct key_signature *)get_first_sig(next_uid->signatures);
                                while(sig_walk != NULL)
                                {
                                        next_sig = sig_walk->next;
					if(sig_walk->the_packet != NULL)
					{
						printf("sig_walk->the_packet\n");
						fflush(0);
                                        	free_packet(&(sig_walk->the_packet));
					}
                                        free(sig_walk);
                                        sig_walk = next_sig;
                                }
                        }
			if(uid_walk->the_packet != NULL)
			{
				printf("uid_walk->the_packet\n");
				fflush(0);
                        	free_packet(&(uid_walk->the_packet));
			}
			if(uid_walk->packet_data != NULL)
			{
				printf("uid_walk->packet_data\n");
				fflush(0);
				free(&(uid_walk->packet_data));
			}
			if(uid_walk->id_data != NULL)
			{
				printf("uid_walk->id_data\n");
				fflush(0);
				free(&(uid_walk->id_data));
			}
			printf("uid_walk\n");
			fflush(0);
                        free(uid_walk);
                        uid_walk = next_uid;
                }

                /* Free Subkeys and Binding Signatures */
                walk_subkey = (struct openPGP_subkey *)get_first_subkey((*pubkey)->subkeys);
                while(walk_subkey != NULL)
                {
                        next_subkey = walk_subkey->next;
                        if(next_subkey != NULL)
                        {
                                sig_walk = (struct key_signature *)get_first_sig(next_subkey->binding_signatures);
                                while(sig_walk != NULL)
                                {
                                        next_sig = sig_walk->next;
					if(sig_walk->the_packet != NULL)
					{
						printf("sig_walk->the_packet\n");
						fflush(0);
                                        	free_packet(&(sig_walk->the_packet));
					}
					printf("sig_walk\n");
					fflush(0);
                                        free(sig_walk);
                                        sig_walk = next_sig;
                                }
                        }
			if(walk_subkey->the_packet != NULL)
			{
				printf("walk_subkey->the_packet\n");
				fflush(0);
                        	free_packet(&(walk_subkey->the_packet));
			}
			printf("walk_subkey\n");
			fflush(0);
                        free(walk_subkey);
                        walk_subkey = next_subkey;
                }

                /* Free Main Pubkey Datastructure */
		printf("pubkey\n");
		fflush(0);
                free((*pubkey));
        }
}

void free_packet(struct openPGP_packet **packet)
{
	if((*packet) != NULL)
	{
		if((*packet)->packet_data != NULL)
		{
			free((*packet)->packet_data);
		}
		if((*packet)->full_packet_data != NULL)
		{
			free((*packet)->full_packet_data);
		}
		/* Modify this to free sub packets */
		free((*packet));
	}
}
