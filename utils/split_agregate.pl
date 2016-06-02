#!/usr/bin/perl -w

use strict;
use warnings;
use feature ':5.10';
use Getopt::Long 'HelpMessage';
use IO::File;
use File::Spec;
use Data::Dumper;

my ( $file, $dir, $column, $clean, $acolumn );

GetOptions(
    'file=s'    => \$file,
    'dir=s'     => \$dir,
    'column=i'  => \$column,
    'acolumn=i' => \$acolumn,
    'help'      => sub { HelpMessage(0) }
) or HelpMessage(1);

die "$0 requires the input file argument (--file)\n"      unless $file;
die "$0 requires the column number argument (--column)\n" unless $column;
die "$0 requires the agregate column number argument (--acolumn)\n"
    unless $acolumn;

$dir = '/tmp' unless $dir;

unlink glob File::Spec->catfile( $dir, '*.csv' );

open FH, '<', $file or die $!;

my ( @rows, $row, $line, $copy, $fh, $i, $headline );
my ( %pages, %voc, $key );

$headline = readline(FH);

while ( $line = <FH> ) {

    $copy = $line;
    chomp $line;

    # Parse .csv file
    $line =~ s/"|\s//g;

    @rows = split ';', $line;
    $row = $rows[$column];
    $key = $rows[ $acolumn ];

    $pages{$row} ||= 0;
    $fh = IO::File->new(
        '>> ' . File::Spec->catfile( $dir, "$row-sum.csv" ) );

    unless ( $pages{$row} ) {
        print $fh $headline;
    }

    print $fh $copy;
    ++$pages{$row};

    $voc{$row}->{$key} ||= 0;
    ++$voc{$row}->{$key};

    undef $fh;

}

my @clust = keys %voc;
my ( $sum, @keys, $freq, $clust, $command );
for $i (@clust) {

    @keys = keys $voc{$i};

    $sum = 0;
    for (@keys) {
        $sum += $voc{$i}->{$_};
    }

    $fh = IO::File->new( '>> ' . File::Spec->catfile( $dir, "$i-freq.csv" ) );
    for (@keys) {
        say $fh sprintf( "%s\t%d\t%.2f%%",
            $_, $voc{$i}->{$_}, ( ( $voc{$i}->{$_} ) / $sum ) * 100 );
    }
    undef $fh;

    $sum   = File::Spec->catfile( $dir, "$i-sum.csv" );
    $freq  = File::Spec->catfile( $dir, "$i-freq.csv" );
    $clust = File::Spec->catfile( $dir, "$i-clust.csv" );

    # $command = "paste $sum $freq > $clust";
    $command = "cat $sum > $clust";
    system $command;
    unlink $sum, $freq;
}


# Split clustering file without whois information
# ./split_agreagte.pl --file 05/249/clustering/xmeans/int10.csv --column 8 --acolumn 2 --dir 05/249/clustering/
# 
# Split clustering file with whois information
# ./split_agreagte.pl --file 05/249/clustering/xmeans/int10.csv --column 8 --acolumn 10 --dir 05/249/clustering/

