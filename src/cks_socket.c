/* cks_socket.c - TCP/IP Socket functions
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

#include "cks_socket.h"


/*  Adapated from W. Richard Stevens: Unix Network Programming */
unsigned int read_line(int skt, unsigned char *buffer, unsigned int read_len)
{
        unsigned char c, *ptr;
        unsigned int n, rc;
        ptr = buffer;
	read_len = read_len -2;

        for(n=1; n < read_len; n++)
        {
                if((rc = read(skt, &c,1)) == 1)
                {
                        *ptr++ = c;
                        if(c == '\n')
                        {
                                break;
                        }
                }
                else if(rc == 0)
                {
                        if(n == 1)
                                return 0;
                        else break;
                }
                else
                        return -1;
        }
        *ptr = 0;

        return n;
}


int write_line_to_socket(int c, char *the_line)
{
	unsigned int status = 0;
	unsigned int count = 0;
        int result = 0;

        count = strlen(the_line);
        while(status != count)
        {
        	result = write(c, the_line + status, count - status);
         	if (result < 0) return result;
        	status += result;
        }

        return status;
}
