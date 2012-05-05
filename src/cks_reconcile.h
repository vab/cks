/* cks_reconcile.h - Synchronization Reconciliation Header file
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

#include "common.h"
#include "cks_constants.h"
#include "datastructures.h"
#include "cks_config.h"
#include "cks_socket.h"
#include "cks_log.h"
#include "db.h"

#include "libpq-fe.h"


int build_full_key_list(void);
int perform_reconciliation(struct d_linked_list *, struct d_linked_list *);
int transmit_reconciliation_keys(void);
int send_key_list(void);
