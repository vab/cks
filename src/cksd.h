/* cksd.h - CryptNET Key Server main header file
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
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "libpq-fe.h"

#include "common.h"
#include "cks_constants.h"
#include "datastructures.h"
#include "merge_keys.h"
#include "cks_config.h"
#include "cks_socket.h"
#include "cks_cache.h"
#include "retrieve.h"
#include "cks_log.h"
#include "radix.h"
#include "parse.h"
#include "keys.h"
#include "cgi.h"

#ifdef HAVE_LIBWRAP
	#include <tcpd.h>
	#include <netdb.h>
	#include <syslog.h>
	#include <sys/socket.h>
	#define TCPDSERVICE "cksd"
	/* These variables must be global */
        int allow_severity=LOG_WARNING ;
        int deny_severity=LOG_WARNING ;
        char *yp_get_default_domain ="" ;
#endif

#define TRUE 1

void sig_chld(int);
int accept_connect(int, struct cks_config *);
int parse_get_request(int , unsigned char *, struct cks_config *);
int send_header(int, unsigned char *);
int send_footer(int);
int retrieve_key_from_db(int, unsigned char *, struct cks_config *);
