#include "cks_parse_v3.h"



int parse_v3_public_key_packet(struct openPGP_packet *packet, struct openPGP_pubkey *key_result)
{
        unsigned int id_loc = 0;
        unsigned int modulus_bytes = 0;
        unsigned int exp_bytes = 0;
        unsigned int exp_start = 0;
        unsigned int total_bytes = 0;
        unsigned int i = 0,j=0;
        unsigned int sec_til_exp = 0;
        unsigned char *buffer = NULL;
        unsigned char *key_pointer = NULL;
        unsigned char fp[32];

	int rslt = 0;

	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_v3_public_key_packet\n");
	#endif

	if( (packet == NULL) || (key_result == NULL) )
	{
		return -1;
	}

        key_result->the_packet = packet;
        key_result->key_version = 0x03;
        key_result->creation_time = (packet->packet_data[1] << 24) + (packet->packet_data[2] << 16) + (packet->packet_data[3] << 8) + packet->packet_data[4];
        rslt = set_pk_algo_type(packet->packet_data[7],key_result->algo);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c: parse_v3_pubkey_key_packet failed in call to set_pk_algo_type.\n"));

		return -1;
	}
        key_result->algo_id = packet->packet_data[7];

        sec_til_exp = (packet->packet_data[5] << 8) + packet->packet_data[6];
        if(sec_til_exp != 0)
        {
                key_result->expiration_time = key_result->creation_time + sec_til_exp;
        }

        key_result->key_size = (packet->packet_data[8] << 8) + packet->packet_data[9];
        modulus_bytes = (key_result->key_size + 7)/8;
        id_loc = modulus_bytes + 9;
        exp_start = id_loc +1;

        /*  I need to modify this code to account for nulls in the data. */
        snprintf(key_result->keyid_t,9,"%.2X%.2X%.2X%.2X",packet->packet_data[--id_loc],packet->packet_data[--id_loc],packet->packet_data[--id_loc],packet->packet_data[id_loc]);

        /* Version 3 does not have the 64bit fkeyid */
        snprintf(key_result->fkeyid_t,9,"%s",key_result->keyid_t);

        /*
            Now we Calculate the fingerprint.  A v3 fingerprint is RSA modulus n and
            RSA exponent e hashed.  So we have to figgure out the size and data of e,
            append that to the data of n and then perform an md5 has on that data which
            will produce the 32byte MD5 hash value aka the key fingerprint.
        */
        exp_bytes = (packet->packet_data[exp_start] << 8) + packet->packet_data[++exp_start];
        exp_bytes = (exp_bytes +7)/8;
        total_bytes = exp_bytes + modulus_bytes;
        buffer = (unsigned char *)malloc(total_bytes+3);
	if(buffer == NULL)
	{
		fprintf(stderr,_("parse.c: malloc call failed for total_bytes.\n"));

		return -1;
	}

        key_pointer = &(packet->packet_data[10]);
        for(i = 0; i < modulus_bytes; i++)
        {
                buffer[j++] = *key_pointer++;
        }
        *key_pointer++;
        *key_pointer++;
        for(i = 0; i < exp_bytes; i++)
        {
                buffer[j++] = *key_pointer++;
        }
        rslt = md5_fingerprint(buffer,total_bytes,fp);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c: parse_v3_pubkey_key_packet failed in call to md5_fingerprint.\n"));
		free(buffer);

		return -1;
	}

        /*  Free Malloc'd Memory */
        if(buffer != NULL)
	{
		free(buffer);
	}

        /*  I need to modify this code to account for nulls in the data. */
        snprintf(key_result->fp_db,33,"%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X",fp[0],fp[1],fp[2],fp[3],fp[4],fp[5],fp[6],fp[7],fp[8],fp[9],fp[10],fp[11],fp[12],fp[13],fp[14],fp[15]);
        snprintf(key_result->fp_t,49,"%.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X  %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X",fp[0],fp[1],fp[2],fp[3],fp[4],fp[5],fp[6],fp[7],fp[8],fp[9],fp[10],fp[11],fp[12],fp[13],fp[14],fp[15]);

	return 0;
}

int parse_v3_sig(struct openPGP_packet *packet, struct key_signature *new_sig)
{
        unsigned int    k = 0, j = 0;
        unsigned int    loop_index = 0;

	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_v3_sig\n");
	#endif

	if( (packet == NULL) || (new_sig == NULL) )
	{
		return -1;
	}

        loop_index = 7;

        for(j=0;j<8;j++)
        {
                new_sig->key_id[k++] = packet->packet_data[loop_index++];
        }
        new_sig->key_id[8] = '\0';
        new_sig->lkeyid = (new_sig->key_id[4] << 24) | (new_sig->key_id[5] << 16) | (new_sig->key_id[6] << 8) | new_sig->key_id[7];


        return 0;
}


int parse_v3_public_subkey(struct openPGP_packet *packet, struct openPGP_pubkey *key_result)
{
        struct openPGP_subkey *the_subkey = NULL;
        unsigned int id_loc = 0;
        unsigned int modulus_bytes = 0;
        unsigned int exp_start = 0;
        unsigned int sec_til_exp = 0;
	int rslt = 0;

	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_v3_public_subkey\n");
	#endif

	if((packet == NULL) || (key_result == NULL))
	{
		return -1;
	}

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
		fprintf(stderr,_("parse.c: call to int_openPGP_subkey failed in parse_v3_public_subkey\n"));
		key_result->key_status = -1;

		return -1;
	}
        the_subkey->the_packet = packet;
        the_subkey->subkey_version = 0x03;
        the_subkey->algo_id = packet->packet_data[7];
        the_subkey->algo[0] = '\0';
        rslt = set_pk_algo_type(packet->packet_data[7],the_subkey->algo);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c: call to set_pk_algo_type failed in parse_v3_public_subkey\n"));
		key_result->key_status = -1;
		/* TODO: Free the subkey */

		return -1;
	}
        the_subkey->keyid[0] = '\0';
        the_subkey->keyid_t[0] = '\0';
        the_subkey->creation_time = (packet->packet_data[1] << 24) + (packet->packet_data[2] << 16) + (packet->packet_data[3] << 8) + packet->packet_data[4];
        the_subkey->expiration_time = 0;
        sec_til_exp = (packet->packet_data[5] << 8) + packet->packet_data[6];
        if(sec_til_exp != 0)
        {
                the_subkey->expiration_time = key_result->creation_time + sec_til_exp;
        }
        the_subkey->key_size = (packet->packet_data[8] << 8) + packet->packet_data[9];
        the_subkey->binding_signatures = NULL;
        the_subkey->next = NULL;
        the_subkey->prev = NULL;

        modulus_bytes = (key_result->key_size + 7)/8;
        id_loc = modulus_bytes + 9;
        exp_start = id_loc +1;

        /*  I need to modify this code to account for nulls in the data. */
        snprintf(the_subkey->keyid_t,9,"%.2X%.2X%.2X%.2X",packet->packet_data[--id_loc],packet->packet_data[--id_loc],packet->packet_data[--id_loc],packet->packet_data[id_loc]);

        rslt = add_subkey(key_result,the_subkey);


        return rslt;
}


int parse_v3_subkey_binding_sig(struct openPGP_packet *packet, struct key_signature *new_sig, struct openPGP_subkey *the_subkey)
{
        unsigned int	k = 0, j = 0;
        unsigned long	loop_index = 0;


	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_v3_subkey_binding_sig\n");
	#endif

	if(packet == NULL) return -1;
	if(new_sig == NULL) return -1;
	if(the_subkey == NULL) return -1;

        loop_index = 7;

        for(j=0;j<8;j++)
        {
                new_sig->key_id[k++] = packet->packet_data[loop_index++];
        }
        new_sig->key_id[8] = '\0';
        new_sig->lkeyid = (new_sig->key_id[4] << 24) | (new_sig->key_id[5] << 16) | (new_sig->key_id[6] << 8) | new_sig->key_id[7];


	return 0;
}

