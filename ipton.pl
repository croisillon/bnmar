#!/usr/bin/perl

use strict;
use warnings;
use Socket;
$|=1;

use constant IN => 'domains.table';
use constant OUT => 'domains.digits.table';

=encoding utf8

=head1 NAME

IP address to Number

=head1 SYNOPSIS

Преобразует ip-адреса в числа

=head1 AUTHOR

Denis Lavrov C<diolavr@gmail.com>

=cut

open my $domain, '<', IN;
open my $table, '>', OUT;

for (<$domain>) {
	if ($_ =~ m/^#/) { next; }
	map { 
		print $table (unpack 'N', Socket::inet_aton($_)), "\n"; 
	} split ',', $_;
}

close ($domain);
close ($table);

__END__
