#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "datastructures.h"
#include "std_types.h"
#include "radix.h"
#include "cgi.h"


int parse_v4_public_key_packet(struct openPGP_packet *, struct openPGP_pubkey *);
int parse_v4_sig_sub_packets(struct openPGP_packet *,struct key_signature *, struct openPGP_pubkey *);

int parse_v4_public_subkey(struct openPGP_packet *, struct openPGP_pubkey *);
int parse_v4_subkey_binding_sig(struct openPGP_packet *, struct key_signature *new_sig, struct openPGP_subkey *);
int parse_v4_subkey_binding_sig_subpackets(struct openPGP_packet *, struct key_signature *, struct openPGP_subkey *);

