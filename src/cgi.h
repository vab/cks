/* cgi.h - CGI functions header file
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

#include <stdio.h>
#include <string.h>

#include "common.h"
#include "datastructures.h"

void print_header(char *);
void print_footer(void);
void print_admin_header(char *);
void print_admin_footer(void);

void	do_error_page(char *);
int	hex_to_ascii(char *);
struct name_value_pair_dllst *parse_name_value_pairs(char *);

void chk_key_version(unsigned char vrsn);
void print_v2_warning(void);
void print_v3_warning(void);

