/* std_types.c - openPGP type flag processing functions
 * Copyright (C) 2001-2011 CryptNET, V. Alex Brennen (VAB)
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

#include "std_types.h"


void echo_packet_type(int pkttype)
{
	printf(_("<p>Packet Type: %d: "), pkttype);
	switch(pkttype)
	{
		case 0:
			fprintf(stderr, _("Packet with Reserved type read!</p>\n"));
			break;
		case 1:
			printf(_("Public-Key Encrypted Session Key Packet</p>\n"));
			break;
		case 2:
			printf(_("Signature Packet.</p>\n"));
			break;
		case 3:
			printf(_("Symmetric-Key Encrypted Session Key Packet.</p>\n"));
			break;
		case 4:
			printf(_("One-Pass Signature Packet.</p>\n"));
			break;
		case 5:
			printf(_("Secret Key Packet.</p>\n"));
			break;
		case 6:
			printf(_("Public Key Packet.</p>\n"));
			break;
		case 7:
			printf(_("Secret Subkey Packet.</p>\n"));
			break;
		case 8:
			printf(_("Compressed Data Packet.</p>\n"));
			break;
		case 9:
			printf(_("Symmetrically Encrypted Data Packet.</p>\n"));
			break;
		case 10:
			printf(_("Marker Packet.</p>\n"));
			break;
		case 11:
			printf(_("Literal Data Packet.</p>\n"));
			break;
		case 12:
			printf(_("Trust Packet.</p>\n"));
			break;
		case 13:
			printf(_("User ID Packet.</p>\n"));
			break;
		case 14:
			printf(_("Public Subkey Packet.</p>\n"));
			break;
		case 16:
			printf("RFC2440 Comment Packet.</p>\n");
			break;
		case 17:
			printf("User Attribute Packet.</p>\n");
			break;
		case 18:
			printf("Sym. Encrypted and Integrity Protected Data Packet.</p>\n");
			break;
		case 19:
			printf("Modification Detection Code Packet.</p>\n");
			break;
		case 60:
		case 61:
		case 62:
		case 63:
			printf(_("Private or Experimental Packet Value.</p>\n"));
			break;
		default:
			printf(_("Unknown Packet Type.</p>\n"));
			break;
	}
}

void echo_sig_type(unsigned char type)
{
	switch(type)
	{
		case 0x01:
			printf(_("Signature of a carnonical text document.\n"));
			break;
		case 0x02:
			printf(_("Standalone singature.\n"));
			break;
		case 0x10:
			printf(_("Generic certification of a User ID and Public Key packet.\n"));
			break;
		case 0x11:
			printf(_("Persona certification of a UserID and Public Key packet.\n"));
			break;
		case 0x12:
			printf(_("Casual certification of a UserID and Pubkey Key packet.\n"));
			break;
		case 0x13:
			printf(_("Positive certificate of a UserID and Pubkey Key Packet.\n"));
			break;
		case 0x18:
			printf(_("Subkey Binding Signature\n"));
			break;
		case 0x19:
			printf(_("Primary Key Binding Signature\n"));
			break;
		case 0x1F:
			printf(_("Signature directly on a key\n"));
			break;
		case 0x20:
			printf(_("Key revocation signature\n"));
			break;
		case 0x28:
			printf(_("Subkey revocation signature\n"));
			break;
		case 0x30:
			printf(_("Certification revocation signature\n"));
			break;
		case 0x40:
			printf(_("Timestamp signature\n"));
			break;
		case 0x50:
			printf(_("Third-Party Confirmation signature\n"));
			break;
		default:
			printf(_("Signature Typing error.\n"));
			break;
	}
}

void echo_sig_subpkt_type(unsigned char type)
{
	switch (type)
	{
		case 2:
			printf(_("Signature Creation Time\n"));
			break;
		case 3:
			printf(_("Signature Expiration Time\n"));
			break;
		case 4:
			printf(_("Exportable Certification\n"));
			break;
		case 5:
			printf(_("Trust Signature\n"));
			break;
		case 6:
			printf(_("Regular Expression\n"));
			break;
		case 7:
			printf(_("Revocable\n"));
			break;
		case 9:
			printf(_("Key Expiration Time\n"));
			break;
		case 10:
			printf(_("Placeholder For Backward Compatibility\n"));
			break;
		case 11:
			printf(_("Preferred Symmetric Algorithms\n"));
			break;
		case 12:
			printf(_("Revocation Key\n"));
			break;
		case 16:
			printf(_("Issuer Key ID\n"));
			break;
		case 20:
			printf(_("Notation Data\n"));
			break;
		case 21:
			printf(_("Preferred Hash Algorithms\n"));
			break;
		case 22:
			printf(_("Preferred Compression Algorithms\n"));
			break;
		case 23:
			printf(_("Key Server Preferences\n"));
			break;
		case 24:
			printf(_("Preferred Key Server\n"));
			break;
		case 25:
			printf(_("Primary User ID\n"));
			break;
		case 26:
			printf(_("Policy URL\n"));
			break;
		case 27:
			printf(_("Key Flags\n"));
			break;
		case 28:
			printf(_("Signer's User ID\n"));
			break;
		case 29:
			printf(_("Reason For Revocation\n"));
			break;
		case 30:
			printf(_("Features\n"));
			break;
		case 31:
			printf(_("Signature Target\n"));
			break;
		case 32:
			printf(_("Embedded Signature\n"));
			break;
		case 100:
		case 101:
		case 102:
		case 103:
		case 104:
		case 105:
		case 106:
		case 107:
		case 108:
		case 109:
		case 110:
			printf(_("Internal or userdefined subpacket.\n"));
			break;
		default:
			printf(_("Signature Subpacket Typing error.\n"));
			break;
	}
}


int set_pk_algo_type(unsigned char algo, unsigned char *buffer)
{
	int return_val = 0;

	switch(algo)
	{
		case 1:
			/* RSA (Encrypt and Sign) */
		case 2:
			/* RSA (Encrypt only) */
		case 3:
			/* RSA (Sign only) */
			memcpy(buffer,"RSA",3);
			buffer[3] = '\0';
			break;
		case 16:
			/* Elgamal (Encrypt-Only) */
			memcpy(buffer,"ELG",3);
			buffer[3] = '\0';
			break;
		case 17:
			/* DSA (Digital Signature Standard) */
			memcpy(buffer,"DSA",3);
			buffer[3] = '\0';
			break;
		case 18:
			/* Reserved for Elliptic Curve */
			memcpy(buffer,"EC ",3);
			buffer[3] = '\0';
			break;
		case 19:
			/* Reserved for ECDSA */
			memcpy(buffer,"ECD",3);
			buffer[3] = '\0';
			break;
		case 20:
			/* Elgamal (Encrypt or Sign) */
			memcpy(buffer,"ELG",3);
			buffer[3] = '\0';
			break;
		case 21:
			/* Reserved for Diffie-Hellman (x9.42 as defined for IETF-S/MIME) */
			memcpy(buffer,"942",3);
			buffer[3] = '\0';
			break;
		case 100:
		case 101:
		case 102:
		case 103:
		case 104:
		case 105:
		case 106:
		case 107:
		case 108:
		case 109:
		case 110:
			printf(_("Private/Experimental algorithm.\n"));
			break;
		default:
			/* pk_algo parse error */
			return_val = -1;
			break;
	}

	return return_val;
}

void echo_hash_algo_type(int algo)
{
	switch(algo)
	{
		case 1:
			printf("MD5\n");
			break;
		case 2:
			printf("SHA-1\n");
			break;
		case 3:
			printf("RIPE-MD/160\n");
			break;
		case 4:
			printf(_("Reserved for double-width SHA (experimental)\n"));
			break;
		case 5:
			printf("MD2\n");
			break;
		case 6:
			printf(_("Reserved for Tiger/192\n"));
			break;
		case 7:
			printf(_("Reserved for HAVAL (5 pass, 160-bit)\n"));
			break;
		case 100:
		case 101:
		case 102:
		case 103:
		case 104:
		case 105:
		case 106:
		case 107:
		case 108:
		case 109:
		case 110:
			printf(_("Private/Experimental algorithm.\n"));
			break;
		default:
			printf(_("pk_algo parse error\n"));
			break;
	}
}

void echo_revocation_reason(unsigned char reason)
{
	switch(reason)
	{
		case 0x00:
			printf(_("No reason specified (key revocations or cert revocations)\n"));
			break;
		case 0x01:
			printf(_("Key is superceded (key revocations)\n"));
			break;
		case 0x02:
			printf(_("Key material has been compromised (key revocations)\n"));
			break;
		case 0x03:
			printf(_("Key is retired and no longer used (key revocations)\n"));
			break;
		case 0x20:
			printf(_("User id information is no longer valid (cert revocations)\n"));
			break;
		default:
			printf(_("Revocation Reason parse error. Invalid Revocation Reason.\n"));
			break;
	}
}
