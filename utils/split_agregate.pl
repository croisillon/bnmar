#!/usr/bin/perl -w

use strict;
use warnings;
use feature ':5.10';
use Getopt::Long 'HelpMessage';
use IO::File;
use File::Spec;
use Data::Dumper;

my ( $in, $dir, $column, $clean );

GetOptions(
    'in=s'     => \$in,
    'dir=s'    => \$dir,
    'column=i' => \$column,
    'help'     => sub { HelpMessage(0) }
) or HelpMessage(1);

unlink glob File::Spec->catfile( $dir, '*.csv' );

open FH, '<', $in or die $!;

my ( @rows, $row, $line, $copy, $fh, $i, $headline );
my ( %pages, %voc );

$i = 0;
while ( $line = <FH> ) {

    $copy = $line;

    unless ($i) {
        $headline = $line;
        $i        = 1;
        next;
    }

    # Parse .csv file
    $line =~ s/\n$//;
    $line =~ s/^\"|\"$//g;
    $line =~ s/\s*//g;

    @rows = split /\",(?:\")?/, $line;
    $row = $rows[$column];

    $pages{$row} ||= 0;
    $fh = IO::File->new( '>> ' . File::Spec->catfile( $dir, "$row-sum.csv" ) );

    unless ( $pages{$row} ) {
        print $fh $headline;
    }

    print $fh $copy;
    ++$pages{$row};

    $voc{$row}->{ $rows[2] } ||= 0;
    ++$voc{$row}->{ $rows[2] };

    undef $fh;

}

my @clust = keys %voc;
my ($sum, @keys, $freq, $clust, $command);
for $i ( @clust ) {

	@keys = keys $voc{$i};

	$sum = 0;
	for ( @keys ) {
		$sum += $voc{$i}->{$_};
	}

	$fh = IO::File->new( '>> ' . File::Spec->catfile( $dir, "$i-freq.csv" ) );
	for ( @keys ) {
		say $fh sprintf("%s\t%d\t%.2f%%",$_, $voc{$i}->{$_}, (($voc{$i}->{$_}) / $sum) * 100);
	}
	undef $fh;

	$sum = File::Spec->catfile( $dir, "$i-sum.csv" );
	$freq = File::Spec->catfile( $dir, "$i-freq.csv" );
	$clust = File::Spec->catfile( $dir, "$i-clust.csv" );

	$command = "paste $sum $freq > $clust";
	system $command;
	unlink $sum, $freq;
}

# ./split_agreagte.pl --in xmeans_clustering.csv --column 7 --dir /tmp
