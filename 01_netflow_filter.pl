#!/usr/bin/perl

use warnings;
use strict;
use feature ':5.10';
use Socket qw(inet_aton);
use Data::Dumper;
use File::Temp qw/ tempfile tempdir /;
use Time::Piece ':override';
use Getopt::Long 'HelpMessage';
use PP;

select STDOUT;
$| = 1;

my ( $file, $out, @ips );

GetOptions(
    'file=s'   => \$file,
    'out=s'    => \$out,
    'ip=s{,}'  => \@ips
) or HelpMessage(1);

@ips = scalar @ips ? @ips : ();

my (%cache, %ips);

BEGIN {

	# Open the file with the converted number in the IP address of the domain (TOP 100)
	# http://www.similarweb.com/country/russian_federation
    open( TABLE, '<', 'dns/table.txt' ) or die $!;
    while (<TABLE>) {

    	next if $_ =~ m/^#/;
    	$_ =~ s/\s//g;

    	if ( $_ =~ m/,/ ) {
			map { $cache{$_} = 1; } split ',', $_;
		} else {
			$cache{$_} = 1;		
		}

    }
    close TABLE;

}

for ( @ips ) {
	$ips{$_} = 1;
}

my ($ip, $port, $line, $copy, $i, $c);
open FH, '<', $file or die $!;
open OUT, '>', $out or die $!;

$i = $c = 0;
while ($line = <FH>) {
	++$c;
	$copy = $line;
	$line = [split /\s+/, $line];
	
	($ip, $port) = (split ':', $line->[6]);

	next if $cache{ $ip };

	next if exists $ips{ "$ip:$port" };

	++$i;
	print OUT $copy;
}

close FH;
close OUT;

say sprintf("Count lines: %d\tRecorded: %d \tFiltered: %d", $c, $i, ($c-$i));

__END__

