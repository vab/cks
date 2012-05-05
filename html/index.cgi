#!/usr/bin/perl

# index.cgi - A Perl program to direct browsers based on language
# Copyright (C) 2001-2004 CryptNET, V. Alex Brennen (VAB)
#
# This file is part of the CryptNET OpenPGP Public Key Server (cks).
#
# cks is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# cks is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

# This script should look at browser information to
# determine the prefered language of the client.

$browser = $ENV{'HTTP_USER_AGENT'};

if($browser =~ "en")
{
	print "Location: en/index.html\n\n";
}
elsif($browser =~ "de")
{
	print "Location: de/index.html\n\n";
}
# If we do not currently support their language we send
# them to the english pages.
else
{
	print "Location: en/index.html\n\n";
}


