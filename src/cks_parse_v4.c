#include "cks_parse_v4.h"


int parse_v4_public_key_packet(struct openPGP_packet *packet, struct openPGP_pubkey *key_result)
{
	int rslt = 0;


	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_v4_public_key_packet\n");
	#endif

	if( (packet == NULL) || (key_result == NULL) )
	{
		return -1;
	}

        key_result->the_packet = packet;
        key_result->key_version = 0x04;
        key_result->creation_time = (packet->packet_data[1] << 24) + (packet->packet_data[2] << 16) + (packet->packet_data[3] << 8) + packet->packet_data[4];
        rslt = set_pk_algo_type(packet->packet_data[5], key_result->algo);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c: parse_v4_pubkey_key_packet failed in call to set_pk_algo_type.\n"));

		return -1;
	}
        key_result->algo_id = packet->packet_data[5];
        key_result->key_size = (packet->packet_data[6] << 8) + packet->packet_data[7];
        rslt = fingerprint(&key_result->buffer[0], packet->packet_length+3, &key_result->fp[0]);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c: parse_v4_pubkey_key_packet failed in call to fingerprint.\n"));

		return -1;
	}
        key_result->special_data[0] = 0x99;
        key_result->special_data[1] = key_result->buffer[1];
        key_result->special_data[2] = key_result->buffer[2];

        /*  I need to modify this code to account for nulls in the data. */
        snprintf(key_result->fp_db, 41, "%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X",key_result->fp[0],key_result->fp[1],key_result->fp[2],key_result->fp[3],key_result->fp[4],key_result->fp[5],key_result->fp[6],key_result->fp[7],key_result->fp[8],key_result->fp[9],key_result->fp[10],key_result->fp[11],key_result->fp[12],key_result->fp[13],key_result->fp[14],key_result->fp[15],key_result->fp[16],key_result->fp[17],key_result->fp[18],key_result->fp[19]);
        snprintf(key_result->fp_t, 61, "%.2X%.2X %.2X%.2X %.2X%.2X %.2X%.2X %.2X%.2X&nbsp;&nbsp;%.2X%.2X %.2X%.2X %.2X%.2X %.2X%.2X %.2X%.2X",key_result->fp[0],key_result->fp[1],key_result->fp[2],key_result->fp[3],key_result->fp[4],key_result->fp[5],key_result->fp[6],key_result->fp[7],key_result->fp[8],key_result->fp[9],key_result->fp[10],key_result->fp[11],key_result->fp[12],key_result->fp[13],key_result->fp[14],key_result->fp[15],key_result->fp[16],key_result->fp[17],key_result->fp[18],key_result->fp[19]);
        snprintf(key_result->keyid_t,9,"%.2X%.2X%.2X%.2X",key_result->fp[16],key_result->fp[17],key_result->fp[18],key_result->fp[19]);
        snprintf(key_result->fkeyid_t,17,"%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X",key_result->fp[12],key_result->fp[13],key_result->fp[14],key_result->fp[15],key_result->fp[16],key_result->fp[17],key_result->fp[18],key_result->fp[19]);


	return 0;
}

int parse_v4_public_subkey(struct openPGP_packet *packet, struct openPGP_pubkey *key_result)
{
        struct openPGP_subkey *the_subkey = NULL;
        unsigned char *tmp_buffer = NULL;
	unsigned int debug_tmp_var = 0;
        int i =0;
        int j=3;
	int rslt = 0;

	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_v4_public_subkey\n");
	#endif


        the_subkey = (struct openPGP_subkey *)malloc(sizeof(struct openPGP_subkey));
	if(the_subkey == NULL)
	{
		fprintf(stderr,_("parse.c: malloc call failed. unable to malloc subkey.\n"));
		key_result->key_status = -1;
		return -1;
	}
	rslt = init_openPGP_subkey(the_subkey);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c: call to int_openPGP_subkey failed in parse_v4_public_subkey\n"));
		key_result->key_status = -1;

		return -1;
	}
        the_subkey->the_packet = packet;
        the_subkey->subkey_version = 0x04;
        the_subkey->algo_id = packet->packet_data[5];
        the_subkey->algo[0] = '\0';
	rslt = set_pk_algo_type(packet->packet_data[5],the_subkey->algo);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c: call to set_pk_algo_type failed in parse_v4_public_subkey\n"));
		key_result->key_status = -1;
		/* TODO: Free the subkey */

		return -1;
	}
        the_subkey->keyid[0] = '\0';
        the_subkey->keyid_t[0] = '\0';
        the_subkey->creation_time = (packet->packet_data[1] << 24) + (packet->packet_data[2] << 16) + (packet->packet_data[3] << 8) + packet->packet_data[4];
        the_subkey->expiration_time = 0;
        the_subkey->fp[0] = '\0';
        the_subkey->key_size = (packet->packet_data[6] << 8) + packet->packet_data[7];

        tmp_buffer = (unsigned char *)malloc(packet->packet_length+4);
	if(tmp_buffer == NULL)
	{
		fprintf(stderr,_("parse.c: call to malloc failed in parse_v4_public_subkey\n"));
		key_result->key_status = -1;

		return -1;
	}
	/* FIXME This is wrong I think */
        tmp_buffer[0] = 0x99;
        tmp_buffer[1] = packet->pkt_len_d[0];
        tmp_buffer[2] = packet->pkt_len_d[1];
        tmp_buffer[3] = '\0';
        for(i = 0; i<packet->packet_length;i++)
        {
        	tmp_buffer[j] = packet->packet_data[i];
		j++;
        }

        debug_tmp_var =packet->packet_length +3;
        rslt = fingerprint(&tmp_buffer[0],debug_tmp_var, &the_subkey->fp[0]);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c: call to fingerprint failed in parse_v4_public_subkey\n"));
		key_result->key_status = -1;
		if(tmp_buffer != NULL)
		{
			free(tmp_buffer);
		}

		return -1;
	}

        snprintf(the_subkey->keyid_t,9,"%.2X%.2X%.2X%.2X",the_subkey->fp[16],the_subkey->fp[17],the_subkey->fp[18],the_subkey->fp[19]);

        rslt = add_subkey(key_result,the_subkey);
	
	if(tmp_buffer != NULL)
		free(tmp_buffer);

	return rslt;
}

int parse_v4_sig_sub_packets(struct openPGP_packet *packet,struct key_signature *new_sig,struct openPGP_pubkey *key_result)
{
        unsigned long    loop_index = 0;
        unsigned long    total_lenbytes =0;
        unsigned long    j = 0;
        unsigned long    k = 0;
        unsigned long    l = 0;
        unsigned long    subpk_length = 0;


	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_v4_sig_sub_packet\n");
	#endif

	if( (packet == NULL) || (new_sig == NULL) )
	{
		return -1;
	}

        total_lenbytes = ((packet->packet_data[4] << 8) + packet->packet_data[5]);
        loop_index = 6;
        total_lenbytes = total_lenbytes+6;

        /* printf("Parsing walk_sig = (struct key_signature *)get_first_sig(walk_id->signatures);
		while(walk_sig != NULL)
		{
			fprintf(stderr,"      pubkey->id->sig: %p\n",walk_sig);
			fprintf(stderr,"      pubkey->id->sig->the_packet: %p\n",walk_sig->the_packet);
			fprintf(stderr,"        pubkey->id->sig->the_packet->packet_data: %p\n",walk_sig->the_packet->packet_data);
			fprintf(stderr,"        pubkey->id->sig->the_packet->full_packet_data: %p\n",walk_sig->the_packet->full_packet_data);
			fprintf(stderr,"      pubkey->id->sig->prev: %p\n",walk_sig->prev);
			fprintf(stderr,"      pubkey->id->sig->next: %p\n",walk_sig->next);

			walk_sig = walk_sig->next;
		}Hashed Sub Packet Data.\n"); */
        while(loop_index < total_lenbytes)
        {
                if(packet->packet_data[loop_index] < 192)
                {
                        subpk_length = packet->packet_data[loop_index++];
                }
                else if((packet->packet_data[loop_index] >= 192) && (packet->packet_data[loop_index] < 255))
                {
                        subpk_length = ((packet->packet_data[loop_index++] << 8) + packet->packet_data[loop_index++]);
                }
		else if(packet->packet_data[loop_index] == 255)
		{
			subpk_length = 0; /* TODO FIXME 4 octet scalar */
		}
           /*     echo_sig_subpkt_type(packet->packet_data[loop_index]); */
                if(packet->packet_data[loop_index] == 0x03)
                {
                        /*  Signature Expiration Time */
 /*                       int tmp_idx = 0;
                        key_result->expiration_time = 0;

                        tmp_idx = loop_index;
                        tmp_idx++;

                        echo_sig_subpkt_type(packet->packet_data[loop_index]);
                        printf("Signature Expiration Time Detected.\n");
                        printf("Subpacket Length: %d\n", subpk_length);
                        key_result->expiration_time = (packet->packet_data[tmp_idx] << 24);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 16);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 8);
                        tmp_idx++;
                        key_result->expiration_time += packet->packet_data[tmp_idx];
                        printf("%s\n",ctime(&(key_result->creation_time)));
                        key_result->expiration_time += key_result->creation_time;
                        printf("0x%0.8x\n", key_result->expiration_time);
                        printf("%s\n",ctime(&(key_result->expiration_time)));
                        fflush(0);
 */
                }
                else if(packet->packet_data[loop_index] == 0x09)
                {
                        int tmp_idx = 0;
                        key_result->expiration_time = 0;

                        tmp_idx = loop_index;
                        tmp_idx++;

                        key_result->expiration_time = (packet->packet_data[tmp_idx] << 24);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 16);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 8);
                        tmp_idx++;
                        key_result->expiration_time += packet->packet_data[tmp_idx];

                        key_result->expiration_time += key_result->creation_time;
                }
                else if(packet->packet_data[loop_index] == 0x10)
                {
                        k = 0;
                        l = 0;
                        l = loop_index;
                        l++;
                        for(j=0;j<8;j++)
                        {
                                new_sig->key_id[k++] = packet->packet_data[l++];
                        }
                        new_sig->lkeyid = (new_sig->key_id[4] << 24) | (new_sig->key_id[5] << 16) | (new_sig->key_id[6] << 8) | new_sig->key_id[7];
                }
		else if(packet->packet_data[loop_index] == 23) /* Keyserver Prefs */
		{
			if(packet->packet_data[loop_index+1] = 0x80)
			{
				/* key_result-> */
				/* TODO FIXME we should set no modify here, but i'm not sure if we
				   should do it on the pubkey or on individual keys and subkeys. */
			}
		}
                else if(packet->packet_data[loop_index] == 29)
                {
                        /* Reason For Revocation */
                        /*
                                0x00 - No reason specified (key revocations or cert revocations)
                                0x01 - Key is superceded (key revocations)
                                0x02 - Key material has been compromised (key revocations)
                                0x03 - Key is no longer used (key revocations)
                                0x20 - User id information is no longer valid (cert revocations)
                        */
                        /*  The Length of the subpackets is the length of the reason plus one */

                }
                for(j=0;j<subpk_length;j++)
                {
			if(loop_index > total_lenbytes)
			{
				fprintf(stderr,"parse.c 1522: Error.\n");
				fprintf(stderr,"Parse Faliled, invalid lengths\n");
				fprintf(stderr,"loop_index: %lu  total_lenbytes: %lu\n", loop_index,total_lenbytes);
				
				return -1;
			}
                        loop_index++;
                }
        }
        /* Start Processing Unhashed subpacket Data. */
        /* printf("Parsing Unhased subpacket Data %d\n", loop_index); */
        /* while(i < packet->packet_length)
        {
                printf("%d: 0x%0.2x\n",i,packet->packet_data[i++]);
        }*/
        /* printf("%d %d\n",loop_index, packet->packet_length); */
        if(loop_index > packet->packet_length)
        {
		fprintf(stderr, _("Invalid Packet.\n"));
                do_error_page(_("Invalid Packet."));

		key_result->key_status = -1;

                return -1;
        }
        total_lenbytes = 0;
        total_lenbytes = (packet->packet_data[loop_index++] << 8);
        total_lenbytes = total_lenbytes + packet->packet_data[loop_index++];
        total_lenbytes = total_lenbytes + loop_index;
        while(loop_index < total_lenbytes)
        {
                if(packet->packet_data[loop_index] < 192)
                {
                        subpk_length = packet->packet_data[loop_index++];
                }
                else
                {
                        subpk_length = ((packet->packet_data[loop_index++] << 8) + packet->packet_data[loop_index++]);
                }
        /*      echo_sig_subpkt_type(packet->packet_data[loop_index]); */
                if(packet->packet_data[loop_index] == 0x03)
                {
 /*                       int tmp_idx = 0;
                        key_result->expiration_time = 0;

                        tmp_idx = loop_index;
                        tmp_idx++;

                        echo_sig_subpkt_type(packet->packet_data[loop_index]);
                        printf("Signature Expiration Time Detected.\n");
                        printf("Subpacket Length: %d\n", subpk_length);
                        key_result->expiration_time = (packet->packet_data[tmp_idx] << 24);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 16);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 8);
                        tmp_idx++;
                        key_result->expiration_time += packet->packet_data[tmp_idx];
                        printf("%s\n",ctime(&(key_result->creation_time)));
                        key_result->expiration_time += key_result->creation_time;
                        printf("0x%0.8x\n", key_result->expiration_time);
                        printf("%s\n",ctime(&(key_result->expiration_time)));
                        fflush(0);
 */
                }
                else if(packet->packet_data[loop_index] == 0x09)
                {
                        int tmp_idx = 0;
                        key_result->expiration_time = 0;

                        tmp_idx = loop_index;
                        tmp_idx++;

                        key_result->expiration_time = (packet->packet_data[tmp_idx] << 24);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 16);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 8);
                        tmp_idx++;
                        key_result->expiration_time += packet->packet_data[tmp_idx];

                        key_result->expiration_time += key_result->creation_time;
                }
                else if(packet->packet_data[loop_index] == 0x10)
                {
                        k = 0;
                        l = 0;
                        l = loop_index;
                        l++;
                        for(j=0;j<8;j++)
                        {
                                new_sig->key_id[k++] = packet->packet_data[l++];
                        }
                        new_sig->lkeyid = (new_sig->key_id[4] << 24) | (new_sig->key_id[5] << 16) | (new_sig->key_id[6] << 8) | new_sig->key_id[7];
                      /*  printf("\n0x%0.8x\n\n",new_sig->lkeyid); */
                }
                loop_index=0;
                for(j=0;j<total_lenbytes;j++)
                {
                        loop_index++;
                }
        }


        return 0;
}


int parse_v4_subkey_binding_sig(struct openPGP_packet *packet, struct key_signature *new_sig, struct openPGP_subkey *the_subkey)
{
	int rslt = 0;

	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_v4_subkey_binding_sig\n");
	#endif

	rslt = parse_v4_subkey_binding_sig_subpackets(packet,new_sig,the_subkey);
	if(rslt == -1)
	{
		fprintf(stderr,"parse.c: call to parse_v4_subkey_binding_sig failed.\n");
	}


	return rslt;
}

/* TODO: rewrite this function. */
int parse_v4_subkey_binding_sig_subpackets(struct openPGP_packet *packet, struct key_signature *new_sig, struct openPGP_subkey *the_subkey)
{
        unsigned long	loop_index = 0;
        unsigned long	total_lenbytes =0;
        unsigned int	j = 0;
        unsigned int	k = 0;
        unsigned int	l = 0;
        unsigned long	subpk_length = 0;
	unsigned int	length_of_length = 0;

	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_v4_subkey_binding_sig_subpackets\n");
	#endif

	/* TODO:  Compliance with RFC2440 Section 5.2.3.1 Parsing */
	/* FIXME:  Lack of compliance is causing segfaults */
	if(packet->packet_data[4] < 192)
	{
		total_lenbytes = packet->packet_data[4];
		length_of_length = 1;
	}
	else if((packet->packet_data[4] >= 192) && (packet->packet_data[4] < 255) )
	{

        	total_lenbytes = (((packet->packet_data[4] - 192) << 8) + (packet->packet_data[5] + 192));
		length_of_length = 2;
	}
	else if(packet->packet_data[4] == 255)
	{
		total_lenbytes = (packet->packet_data[5] << 24) | (packet->packet_data[6] << 16)
		  | (packet->packet_data[7] << 8)  | packet->packet_data[8];
		  length_of_length = 5;
	}
	else
	{
		fprintf(stderr,"packet parse error. unable to determine length from header\n");

		return -1;
	}
        loop_index = 4 + length_of_length;
        total_lenbytes = total_lenbytes+6;

        /* printf("Parsing Hashed Sub Packet Data.\n"); */
        while(loop_index < total_lenbytes)
        {

		if(packet->packet_data[loop_index] < 192)
                {
                        subpk_length = packet->packet_data[loop_index++];
                }
                else if((packet->packet_data[loop_index] >= 192) && (packet->packet_data[loop_index] < 255) )
                {
                        subpk_length = (((packet->packet_data[loop_index++] - 192) << 8) +
				packet->packet_data[loop_index++] + 192);
                }
		else if(packet->packet_data[loop_index] == 255)
		{
			loop_index++;
			subpk_length = (packet->packet_data[loop_index++] << 24) |
				(packet->packet_data[loop_index++] << 16) |
				(packet->packet_data[loop_index++] << 8)  | packet->packet_data[loop_index++];
			length_of_length = 5;
		}
		else
		{
			fprintf(stderr,"Subpacket parse error.  Unable to determine length\n");

			return -1;
		}
		/*
			2 = signature creation time
			3 = signature expiration time
			4 = exportable certification
			5 = trust signature
			6 = regular expression
			7 = revocable
			9 = key expiration time
			10 = placeholder for backward compatibility
			11 = preferred symmetric algorithms
			12 = revocation key
			16 = issuer key ID
			20 = notation data
			21 = preferred hash algorithms
			22 = preferred compression algorithms
			23 = key server preferences
			24 = preferred key server
			25 = primary user id
			26 = policy URL
			27 = key flags
			28 = signer's user id
			29 = reason for revocation
			30 = features
			31 = signature target
			32 = embedded signature
			100 to 110 = internal or user-defined
		*/

           /*   echo_sig_subpkt_type(packet->packet_data[loop_index]); */
                if(packet->packet_data[loop_index] == 0x03)
                {
 /*                       int tmp_idx = 0;
                        key_result->expiration_time = 0;

                        tmp_idx = loop_index;
                        tmp_idx++;

                        echo_sig_subpkt_type(packet->packet_data[loop_index]);
                        printf("Signature Expiration Time Detected.\n");
                        printf("Subpacket Length: %d\n", subpk_length);
                        key_result->expiration_time = (packet->packet_data[tmp_idx] << 24);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 16);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 8);
                        tmp_idx++;
                        key_result->expiration_time += packet->packet_data[tmp_idx];
                        printf("%s\n",ctime(&(key_result->creation_time)));
                        key_result->expiration_time += key_result->creation_time;
                        printf("0x%0.8x\n", key_result->expiration_time);
                        printf("%s\n",ctime(&(key_result->expiration_time)));
                        fflush(0);
 */
                }
                else if(packet->packet_data[loop_index] == 0x09)
                {
                        int tmp_idx = 0;
                        the_subkey->expiration_time = 0;

                        tmp_idx = loop_index;
                        tmp_idx++;

                        the_subkey->expiration_time = (packet->packet_data[tmp_idx] << 24);
                        tmp_idx++;
                        the_subkey->expiration_time += (packet->packet_data[tmp_idx] << 16);
                        tmp_idx++;
                        the_subkey->expiration_time += (packet->packet_data[tmp_idx] << 8);
                        tmp_idx++;
                        the_subkey->expiration_time += packet->packet_data[tmp_idx];

                        the_subkey->expiration_time += the_subkey->creation_time;
                }
                else if(packet->packet_data[loop_index] == 0x10)
                {
                        k = 0;
                        l = 0;
                        l = loop_index;
                        l++;
                        for(j=0;j<8;j++)
                        {
                                new_sig->key_id[k++] = packet->packet_data[l++];
                        }
                        new_sig->lkeyid = (new_sig->key_id[4] << 24) | (new_sig->key_id[5] << 16) | (new_sig->key_id[6] << 8) | new_sig->key_id[7];
                }
                else if(packet->packet_data[loop_index] == 0x26)
                {
                	/* policy URI */
                }
                for(j=0;j<subpk_length;j++)
                {
                        loop_index++;
                }
        }
        /* Start Processing Unhashed subpacket Data. */
        /* printf("Parsing Unhased subpacket Data %d\n", loop_index); */
        /* while(i < packet->packet_length)
        {
                printf("%d: 0x%0.2x\n",i,packet->packet_data[i++]);
        }*/
        /* printf("%d %d\n",loop_index, packet->packet_length); */
 /*       if(loop_index > packet->packet_length)
        {
		fprintf(stderr,_("Invalid Packet in subkey. This error should never occur. Possible corrupt keyring?\n"));

                return -1;
        }
	if(packet->packet_data[loop_index] < 192)
	{
		total_lenbytes = packet->packet_data[loop_index];
		length_of_length = 1;
	}
	else if((packet->packet_data[loop_index] >= 192) && (packet->packet_data[loop_index] < 255) )
	{

        	total_lenbytes = (((packet->packet_data[loop_index++] - 192) << 8) + (packet->packet_data[loop_index] + 192));
		length_of_length = 2;
	}
	else if(packet->packet_data[4] == 255)
	{
		total_lenbytes = (packet->packet_data[5] << 24) | (packet->packet_data[6] << 16)
		  | (packet->packet_data[7] << 8)  | packet->packet_data[8];
		  length_of_length = 5;
	}
	else
	{
		fprintf(stderr,"packet parse error. unable to determine length from header\n");

		return -1;
	}
        loop_index = 4 + length_of_length;
        total_lenbytes = total_lenbytes+6;
        total_lenbytes = 0;
        total_lenbytes = (packet->packet_data[loop_index++] << 8);
        total_lenbytes = total_lenbytes + packet->packet_data[loop_index++];
        total_lenbytes = total_lenbytes + loop_index;
        while(loop_index < total_lenbytes)
        {
		if(packet->packet_data[loop_index] < 192)
                {
                        subpk_length = packet->packet_data[loop_index++];
                }
                else if((packet->packet_data[loop_index] >= 192) && (packet->packet_data[loop_index] < 255) )
                {
                        subpk_length = (((packet->packet_data[loop_index++] - 192) << 8) +
				packet->packet_data[loop_index++] + 192);
                }
		else if(packet->packet_data[loop_index] == 255)
		{
			loop_index++;
			subpk_length = (packet->packet_data[loop_index++] << 24) |
				(packet->packet_data[loop_index++] << 16) |
				(packet->packet_data[loop_index++] << 8)  | packet->packet_data[loop_index++];
			length_of_length = 5;
		}
		else
		{
			fprintf(stderr,"Subpacket parse error.  Unable to determine length\n");

			return -1;
		}

        /*      echo_sig_subpkt_type(packet->packet_data[loop_index]); *//*
                if(packet->packet_data[loop_index] == 0x03)
                {
 *//*                       int tmp_idx = 0;
                        key_result->expiration_time = 0;

                        tmp_idx = loop_index;
                        tmp_idx++;

                        echo_sig_subpkt_type(packet->packet_data[loop_index]);
                        printf("Signature Expiration Time Detected.\n");
                        printf("Subpacket Length: %d\n", subpk_length);
                        key_result->expiration_time = (packet->packet_data[tmp_idx] << 24);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 16);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 8);
                        tmp_idx++;
                        key_result->expiration_time += packet->packet_data[tmp_idx];
                        printf("%s\n",ctime(&(key_result->creation_time)));
                        key_result->expiration_time += key_result->creation_time;
                        printf("0x%0.8x\n", key_result->expiration_time);
                        printf("%s\n",ctime(&(key_result->expiration_time)));
                        fflush(0);
 *//*
                }
                else if(packet->packet_data[loop_index] == 0x09)
                {
                        int tmp_idx = 0;
                        the_subkey->expiration_time = 0;

                        tmp_idx = loop_index;
                        tmp_idx++;

                        the_subkey->expiration_time = (packet->packet_data[tmp_idx] << 24);
                        tmp_idx++;
                        the_subkey->expiration_time += (packet->packet_data[tmp_idx] << 16);
                        tmp_idx++;
                        the_subkey->expiration_time += (packet->packet_data[tmp_idx] << 8);
                        tmp_idx++;
                        the_subkey->expiration_time += packet->packet_data[tmp_idx];

                        the_subkey->expiration_time += the_subkey->creation_time;
                }
                else if(packet->packet_data[loop_index] == 0x10)
                {
                        k = 0;
                        l = 0;
                        l = loop_index;
                        l++;
                        for(j=0;j<8;j++)
                        {
                                new_sig->key_id[k++] = packet->packet_data[l++];
                        }
                        new_sig->lkeyid = (new_sig->key_id[4] << 24) | (new_sig->key_id[5] << 16) | (new_sig->key_id[6] << 8) | new_sig->key_id[7];
                        printf("\n0x%0.8x\n\n",new_sig->lkeyid);
                }
                loop_index=0;
                for(j=0;j<total_lenbytes;j++)
                {
                        loop_index++;
                }
        }*/


        return 0;
}

