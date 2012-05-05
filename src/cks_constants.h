/* cks_constants.h - CKS constant values
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

/* Source */
#define D_SOURCE_CKSD           0
#define D_SOURCE_ADD_CGI        1
#define D_SOURCE_SEARCH_CGI     2
#define D_SOURCE_MAIL_SYNC      3
#define D_SOURCE_CKS_IMPORT     4
#define D_SOURCE_CKS_MAIL_UTIL  5
 
/* db_add_key_results */
#define D_KEY_ADDED             0
#define D_KEY_EXISTS            1
#define D_KEY_MERGED            2
#define D_KEY_REJECTED          3
#define D_KEY_ADDITION_FAILED   -1

#define D_CKS_MAX_LEN		256000
