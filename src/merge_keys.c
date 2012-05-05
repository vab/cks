/* merge_keys.c - Key Merger and Reconstruction functions
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

#include "merge_keys.h"


int compare_keys(struct openPGP_pubkey *new_key, struct openPGP_pubkey *old_key)
{
	int radix_differs = 0;

	radix_differs = strcmp(new_key->radix_data,old_key->radix_data);
	#ifdef DEBUG
	if(radix_differs != 0)
	{
		fprintf(stderr,"Radix Differs: %d\n", radix_differs);
		fprintf(stderr,"new_key->radix_data:\n%s\n\n", new_key->radix_data);
		fprintf(stderr,"old_key->radix_data:\n%s\n\n", old_key->radix_data);
	}
	#endif

	return radix_differs;
}

/*
    This is a little confusing so pay attention.  new_key in this context is
    the new submitted key.  old_key is the key we have in the database.  Since
    we might have data that the new_key doesn't we merge into the old_key
    producing the "new new_key" that we want to store in the db in the old_key
    malloc'd region.
*/
int merge_keys(struct openPGP_pubkey *new_key, struct openPGP_pubkey *old_key)
{
	struct user_id		*walk_id_old = NULL;
	struct user_id		*walk_id_new = NULL;
	struct user_id		*next_id = NULL;
	struct user_id		*last_id = NULL;

	unsigned int new_stuff = 0;
	unsigned int id_found = 0;
	int result = 0;


	#ifdef DEBUG
	fprintf(stderr,"Merge keys called.\n");
	#endif

	walk_id_new = (struct user_id *)get_first_uid(new_key->ids);
	if(walk_id_new == NULL)
	{
		fprintf(stderr,_("merge_keys.c: get_first_uid failed and returned NULL.\n"));
		new_key->key_status = -1;

		return -1;
	}
	while(walk_id_new != NULL)
	{
		walk_id_old = (struct user_id *)get_first_uid(old_key->ids);
		while(walk_id_old != NULL)
		{
			if(strcmp(walk_id_new->id_data,walk_id_old->id_data) == 0)
			{
				id_found = 1;
				break;
			}
			walk_id_old = walk_id_old->next;
		}
		
		/* The ID was not found. So it is added to the key from the keyservers database */
		if(!id_found)
		{
			#ifdef DEBUG
			fprintf(stderr,"New ID Found\n");
			#endif
			new_stuff = 1;
			/* Append UID and Signatures */
			last_id = (struct user_id *)get_last_uid(old_key->ids);
			if(last_id == NULL)
			{
				next_id = walk_id_new->next;
				extract_uid(walk_id_new);

				last_id = walk_id_new;
				last_id->next = NULL;
			}
			else
			{
				next_id = walk_id_new->next;
				extract_uid(walk_id_new);

				last_id->next = walk_id_new;
				last_id = walk_id_new;
				last_id->next = NULL;
			}
		}
		else
		{
			/* The ID is not new. So, we move on to merging the signature packets */
			result = merge_signatures(walk_id_new, walk_id_old);
			if(result == -1)
			{
				fprintf(stderr,_("merge_keys.c: merge_signatures failure.\n"));
				new_key->key_status = -1;

				return -1;
			}
			else if(result == 1)
			{
				new_stuff = 1;
			}
		}
		if(!id_found)
		{
			walk_id_new = next_id;
		}
		else
		{
			id_found = 0;
			walk_id_new = walk_id_new->next;
		}
	}

	result = merge_subkeys(new_key->subkeys,old_key->subkeys);
	if(result == -1)
	{
		fprintf(stderr,_("merge_keys.c:  merge_subkeys failure.\n"));
		new_key->key_status = -1;

		return -1;
	}
	else if(result == 1)
	{
		new_stuff = 1;
	}

	return new_stuff;
}


int merge_signatures(struct user_id *id_new, struct user_id *id_old)
{
	struct key_signature *source_walk_sig = NULL;
	struct key_signature *target_walk_sig = NULL;
	struct key_signature *next_walk_sig = NULL;
	struct key_signature *last_sig = NULL;
	struct key_signature *first_sig = NULL;

	unsigned int sig_found = 0;
	unsigned int new_stuff = 0;


	#ifdef DEBUG
	fprintf(stderr,"merge_signatures called.\n");
	#endif
        source_walk_sig = (struct key_signature *)get_first_sig(id_new->signatures);
	if(source_walk_sig == NULL)
	{
		return 0;
	}
        first_sig = source_walk_sig;
        id_new->signatures = first_sig;

        while(source_walk_sig != NULL)
        {
                sig_found = 0;
                if(id_old == NULL)
                {
                	return 0;
		}
                if(id_old->signatures == NULL) { return 0; }
                target_walk_sig = (struct key_signature *)get_first_sig(id_old->signatures);
                while(target_walk_sig != NULL)
                {
                        sig_found = compare_signatures(source_walk_sig,target_walk_sig);
                        if(sig_found)
                        {
                                break;
                        }
                        target_walk_sig = target_walk_sig->next;
                }
                if(!sig_found)
                {
			#ifdef DEBUG
			fprintf(stderr,"New sig Found\n");
			#endif
			new_stuff = 1;
                        last_sig = (struct key_signature *)get_last_sig(id_old->signatures);
                        last_sig->next = source_walk_sig;
                        next_walk_sig = source_walk_sig->next;
                        extract_sig(source_walk_sig);
                        source_walk_sig->prev = last_sig;
                        last_sig = source_walk_sig;
                        last_sig->next = NULL;
                        source_walk_sig = next_walk_sig;
                }
                else
                {
			sig_found = 0;
                        source_walk_sig = source_walk_sig->next;
                }
        }

        return new_stuff;
}


int compare_signatures(struct key_signature *sig_0,struct key_signature *sig_1)
{
        unsigned int same = 0;
/*
        printf("<BR>Comparison:\n");
        printf("<UL><PRE>\n");
        printf("     0x%0.2x 0x%0.2x\n", sig_0->sig_type, sig_1->sig_type);
        printf("     0x%0.8x 0x%0.8x\n", sig_0->lkeyid, sig_1->lkeyid);
        printf("     0x%0.8x 0x%0.8x\n", sig_0->creation_time, sig_1->creation_time);
        printf("</PRE></UL>\n");
*/
        /* What should you do about creation time, Alex? */
        /*
                &&
                (sig_0->creation_time == sig_1->creation_time)
        */
        if(
                (sig_0->sig_type == sig_1->sig_type) &&
                (sig_0->lkeyid == sig_1->lkeyid)
          )
        {
                same = 1;
        }

        return same;
}


int merge_subkeys(struct openPGP_subkey *new_subkey, struct openPGP_subkey *old_subkey)
{
        struct openPGP_subkey   *walk_subkey_new = NULL;
        struct openPGP_subkey	*walk_subkey_old = NULL;
        struct openPGP_subkey	*last_subkey = NULL;
        struct openPGP_subkey	*next_subkey = NULL;
	unsigned int new_stuff = 0;
        unsigned int subkey_found = 0;
	int rslt = 0;

	#ifdef DEBUG
	fprintf(stderr,"merge_subkeys called.\n");
	#endif
        walk_subkey_new = (struct openPGP_subkey *)get_first_subkey(new_subkey);

        while(walk_subkey_new != NULL)
        {
                subkey_found = 0;
                walk_subkey_old = (struct openPGP_subkey *)get_first_subkey(old_subkey);
                while(walk_subkey_old != NULL)
                {
                	if( (strncmp(walk_subkey_old->keyid_t,walk_subkey_new->keyid_t,10) == 0) )
                        {
                                subkey_found = 1;
                                break;
                        }
                        walk_subkey_old = walk_subkey_old->next;
                }
                if(!subkey_found)
                {
			#ifdef DEBUG
			fprintf(stderr,"New subkey Found\n");
			#endif
			new_stuff = 1;
                        last_subkey = (struct openPGP_subkey *)get_last_subkey(old_subkey);
			if(last_subkey == NULL)
			{
                        	next_subkey = walk_subkey_new->next;
                        	extract_subkey(walk_subkey_new);

                        	last_subkey = walk_subkey_new;
                        	last_subkey->next = NULL;
			}
			else
			{
                        	next_subkey = walk_subkey_new->next;
                        	extract_subkey(walk_subkey_new);

                        	last_subkey->next = walk_subkey_new;
                        	last_subkey = walk_subkey_new;
                        	last_subkey->next = NULL;
			}
                }
                else
                {
                        rslt = merge_binding_signatures(walk_subkey_new, walk_subkey_old);
			if(rslt == -1)
			{
				return rslt;
			}
                }
                if(!subkey_found)
                {
                        walk_subkey_new = next_subkey;
                }
                else
                {
			subkey_found = 0;
                        walk_subkey_new = walk_subkey_new->next;
                }
        }

	return new_stuff;
}


int merge_binding_signatures(struct openPGP_subkey *new_subkey, struct openPGP_subkey *old_subkey)
{
	/* Don't know what the RFC says, but GnuPG says we gotta Merge 'em. */
        struct key_signature *source_walk_sig = NULL;
        struct key_signature *target_walk_sig = NULL;
        struct key_signature *next_walk_sig = NULL;
        struct key_signature *last_sig = NULL;
        struct key_signature *first_sig = NULL;

        unsigned int sig_found = 0;
	unsigned int new_stuff = 0;


	#ifdef DEBUG
	fprintf(stderr,"merge_binding_signatures called.\n");
	#endif
	source_walk_sig = (struct key_signature *)get_first_sig(new_subkey->binding_signatures);
        first_sig = source_walk_sig;
        new_subkey->binding_signatures = first_sig;

        while(source_walk_sig != NULL)
        {
                sig_found = 0;
                if(old_subkey == NULL)
                {
                	return 0;
		}
                if(old_subkey->binding_signatures == NULL) { return 0; }
                target_walk_sig = (struct key_signature *)get_first_sig(old_subkey->binding_signatures);
                while(target_walk_sig != NULL)
                {
                        sig_found = compare_signatures(source_walk_sig,target_walk_sig);
                        if(sig_found)
                        {
                                break;
                        }
                        target_walk_sig = target_walk_sig->next;
                }
                if(!sig_found)
                {
			#ifdef DEBUG
			fprintf(stderr,"New subkey binding signature Found\n");
			#endif
			new_stuff = 1;
                        last_sig = (struct key_signature *)get_last_sig(old_subkey->binding_signatures);
                        last_sig->next = source_walk_sig;
                        next_walk_sig = source_walk_sig->next;
                        extract_sig(source_walk_sig);
                        source_walk_sig->prev = last_sig;
                        last_sig = source_walk_sig;
                        last_sig->next = NULL;
                        source_walk_sig = next_walk_sig;
                }
                else
                {
			sig_found = 0;
                        source_walk_sig = source_walk_sig->next;
                }
        }

        return new_stuff;
}


int build_new_radix_data(struct openPGP_pubkey *pubkey)
{
        struct user_id *walk_id = NULL;
        struct key_signature *walk_sig = NULL;
        struct openPGP_subkey *walk_subkey = NULL;
        unsigned char *buffer = NULL;
        unsigned long buf_len = 0;
        unsigned long encoded = 0;
        unsigned char *decoded = NULL;
        unsigned int decoded_length = 0;
        unsigned char decoded_cksum[5];

        int checksum = 0;
	int result = 0;


	memset(decoded_cksum,0x00,5);
        buffer = (unsigned char *)malloc((strlen(pubkey->radix_data)) *2);
	if(buffer == NULL)
	{
		fprintf(stderr,_("merge_keys.c:  Malloc call failed: out of memory!\n"));
		pubkey->key_status = -1;

		return -1;
	}
        memset(buffer,0x00,((strlen(pubkey->radix_data)) *2));
        decoded = (unsigned char *)malloc((strlen(pubkey->radix_data)) *2);
	if(decoded == NULL)
	{
		fprintf(stderr,_("merge_keys.c:  Malloc call failed: out of memory!\n"));
		if(buffer != NULL)
		{
			free(buffer);
		}

		pubkey->key_status = -1;

		return -1;
	}
        memset(decoded,0x00,((strlen(pubkey->radix_data)) *2));
        decoded_length = decode_buffer(pubkey->radix_data,decoded);
	if(decoded_length == 0)
	{
		fprintf(stderr,_("merge_keys.c:  error null buffer decoded length is 0.\n"));
		if(buffer != NULL)
		{
			free(buffer);
		}
		if(decoded != NULL)
		{
			free(decoded);
		}
		pubkey->key_status = -1;

		return -1;
	}
   /*     for(i=0;i<decoded_length;i++)
        {
                printf("%d: 0x%0.2x\n",i, decoded[i]);
        }
*/
        memset(pubkey->radix_data,0x00,strlen(pubkey->radix_data));

	if(pubkey->the_packet == NULL)
	{
		fprintf(stderr,_("merge_keys.c: pubkey->the_packet is null.\n"));
		if(buffer != NULL)
		{
			free(buffer);
		}
		if(decoded != NULL)
		{
			free(decoded);
		}
		pubkey->key_status = -1;

		return -1;
	}
        /*  Now we have to walk the pubkey */
        result = append_packet_to_buffer(pubkey->the_packet,buffer,buf_len);
	if(result == -1)
	{
		fprintf(stderr,_("merge_keys.c: Failed to append packet to buffer in merge keys.\n"));
		if(buffer != NULL)
		{
			free(buffer);
		}
		if(decoded != NULL)
		{
			free(decoded);
		}
		pubkey->key_status = -1;

		return -1;
	}

        buf_len += pubkey->the_packet->full_packet_length;

        walk_id = (struct user_id *)get_first_uid(pubkey->ids);
	if(walk_id == NULL)
	{
		fprintf(stderr,_("merge_keys.c: walk_id returned NULL.\n"));
		if(buffer != NULL)
		{
			free(buffer);
		}
		if(decoded != NULL)
		{
			free(decoded);
		}
		pubkey->key_status = -1;

		return -1;
	}

        while(walk_id != NULL)
        {
                /* Appending a UID */
                result = append_packet_to_buffer(walk_id->the_packet,buffer,buf_len);
		if(result == -1)
		{
			fprintf(stderr,_("merge_keys.c: Failed to append packet to buffer (UID).\n"));
			if(buffer != NULL)
			{
				free(buffer);
			}
			if(decoded != NULL)
			{
				free(decoded);
			}
			pubkey->key_status = -1;

			return -1;
		}
                buf_len += walk_id->the_packet->full_packet_length;

                walk_sig = (struct key_signature *)get_first_sig(walk_id->signatures);
		if(walk_sig == NULL)
		{
			walk_id->signatures = NULL;
		}
                while(walk_sig != NULL)
                {
                        /* Appending A Signature */
                    /*    printf("appending a signature\n", walk_sig->key_id); */
                        result = append_packet_to_buffer(walk_sig->the_packet,buffer,buf_len);
			if(result == -1)
			{
				fprintf(stderr,_("merge_keys.c: Failed to append packet to buffer (signature).\n"));
				if(buffer != NULL)
				{
					free(buffer);
				}
				if(decoded != NULL)
				{
					free(decoded);
				}
					pubkey->key_status = -1;

				return -1;
			}
                        buf_len += walk_sig->the_packet->full_packet_length;

                        walk_sig = walk_sig->next;
                }
                walk_id = walk_id->next;
        }

        walk_subkey = (struct openPGP_subkey *)get_first_subkey(pubkey->subkeys);
	if(walk_subkey == NULL)
	{
		pubkey->subkeys = NULL;
	}
        while(walk_subkey != NULL)
        {
                /* Appending A Subkey */
		/* printf("appending a Subkey: %s\n",walk_subkey->keyid_t); */
                result = append_packet_to_buffer(walk_subkey->the_packet,buffer,buf_len);
		if(result == -1)
		{
			fprintf(stderr,_("merge_keys.c: Failed to append packet to buffer (subkey).\n"));
			if(buffer != NULL)
			{
				free(buffer);
			}
			if(decoded != NULL)
			{
				free(decoded);
			}

			pubkey->key_status = -1;

			return -1;
		}

                buf_len += walk_subkey->the_packet->full_packet_length;

                /* Walk Subkey Binding Signatures */
                walk_sig = (struct key_signature *)get_first_sig(walk_subkey->binding_signatures);
		if(walk_sig == NULL)
		{
			walk_subkey->binding_signatures = NULL;
		}
                /*
                    I need to look more closely at the standard.  Maybe you can't have more
                    than one binding sig?
                */
                while(walk_sig != NULL)
                {
                        /* Appending a Subkey Signature */
			/* printf("appending a subkey binding signature\n"); */
                        result = append_packet_to_buffer(walk_sig->the_packet,buffer,buf_len);
			if(result == -1)
			{
				fprintf(stderr,_("merge_keys.c: Failed to append packet to buffer (subkey binding sig).\n"));
				if(buffer != NULL)
				{
					free(buffer);
				}
				if(decoded != NULL)
				{
					free(decoded);
				}

				pubkey->key_status = -1;

				return -1;
			}
                        buf_len += walk_sig->the_packet->full_packet_length;

                        walk_sig = walk_sig->next;
                }
                walk_subkey = walk_subkey->next;
        }

        /*  Radix encode the new key */
        encoded = encode_buffer(buffer, pubkey->radix_data,buf_len);

        /* Calc the checksum */
        checksum = radix_checksum(buffer,buf_len);

        /*Break the checksum down into bytes so that I can radix encode it */
        pubkey->encoded_cksum[0] = (checksum >> 16) & 0x000000FF;
        pubkey->encoded_cksum[1] = (checksum >> 8) & 0x000000FF;
        pubkey->encoded_cksum[2] = checksum & 0x000000FF;
        pubkey->encoded_cksum[3] = '\0';
        pubkey->encoded_cksum[4] = '\0';

        encoded = encode_buffer(pubkey->encoded_cksum, decoded_cksum,3);
        snprintf(pubkey->encoded_cksum, 5, "%c%c%c%c", decoded_cksum[0],decoded_cksum[1],decoded_cksum[2],decoded_cksum[3]);

	#ifdef DEBUG
	fprintf(stderr,"New Radix created with cksum: %s\n",pubkey->encoded_cksum);
	fprintf(stderr,"Radix Data:\n%s\n\n",pubkey->radix_data);
	#endif

	if(decoded != NULL)
	{
		free(decoded);
	}
	if(buffer != NULL)
	{
		free(buffer);
	}


        return 0;
}


int append_packet_to_buffer(struct openPGP_packet *packet, unsigned char *buffer,unsigned long len)
{
	unsigned int loop_index = 0;


	if((packet == NULL) || (buffer == NULL) )
	{
		fprintf(stderr,_("append_packet_to_buffer was passed a NULL packet or buffer!\n"));

		return -1;
	}
	if(packet->full_packet_length == 0)
	{
		fprintf(stderr,_("merge_keys.c: append_packet_to_buffer encountered a zero length packet!\n"));

		return -1;
	}

        loop_index = 0;
        while(loop_index < packet->full_packet_length)
        {
                buffer[len] = packet->full_packet_data[loop_index];
                /* Print out all the packet data with indexes by uncommenting the line below - for debugging merges */
                /* printf("%d:  %d: 0x%0.2x\n",len, loop_index, packet->full_packet_data[loop_index]); */
                loop_index++;
                len++;
        }
	/*  When debugging uncommenting this will provide an index to look at the merged binary data against. */
	/*  printf("%d\n",loop_index);*/


	return 0;
}
