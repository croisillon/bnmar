#!/usr/bin/perl

use strict;
use warnings;
use Socket;
$|=1;

open my $domain, '<', 'domains.table';

open my $table, '>', 'domains.digits.table';

for (<$domain>) {
	if ($_ =~ m/^#/) { next; }
	map { 
		print $table (unpack 'N', Socket::inet_aton($_)), "\n"; 
	} split ',', $_;
}

close ($domain);
close ($table);

