#!/usr/bin/perl

use strict;
use warnings;
use Data::Dumper;
use feature ':5.10';
use File::Spec;
use Getopt::Long 'HelpMessage';

my ( $DIR, $OUT, $SUM );

GetOptions(
    'dir=s' => \$DIR,
    'out=s' => \$OUT,
    'sum'   => \$SUM,
    'help'  => sub { HelpMessage(0) }
) or HelpMessage(1);

die "$0 requires the input dir argument (--dir)\n"    unless $DIR;
die "$0 requires the input output argument (--out)\n" unless $OUT;

unless ($SUM) {
    my @list = glob File::Spec->catdir( $DIR, '*' );

    my %data;
    for my $file (@list) {
        next unless -f $file;

        my $filename = [ File::Spec->splitdir($file) ]->[-1];

        open my $fh, '<', $file or die $!;

        my ( $cluster, $ip, @arr );
        while ( my $line = <$fh> ) {
            next if $line !~ m/\d/;

            ( undef, undef, $ip, @arr ) = ( split ';', $line );
            $ip =~ s/"//g;
            $cluster = $arr[-2];
            $cluster =~ s/\D//g;

            $data{$filename}->{$cluster}->{$ip} ||= [];
            push @{ $data{$filename}->{$cluster}->{$ip} }, $line;
        }

        close $fh;
        undef $fh;
    }

    my @cls;
    for my $filename ( keys %data ) {

        for my $cluster ( keys %{ $data{$filename} } ) {

            if ( 1 == scalar keys %{ $data{$filename}->{$cluster} } ) {
                push @cls, [ [ keys %{ $data{$filename}->{$cluster} } ]->[0], $filename, $cluster ];
            }

            # say Dumper keys %{ $data{$filename}->{$cluster} };
        }
    }

    open my $fh, '>', $OUT or die $!;

    for (@cls) {
        say $fh join ';', @{$_};
    }

    close $fh;
    undef $fh;

}
else {

    my @found = glob File::Spec->catfile( $DIR, '*' );

    my ( @files, %data, %ips );

    for my $file (@found) {
        next unless -f $file;

        push @files, $file;

        open my $fh, '<', $file or die $!;

        while ( my $line = <$fh> ) {
            next unless ( $line =~ m/^\d/ );

            my @arr = split ';', $line;

            $ips{$file}->{ $arr[0] } = 1;
            push @{$data{$file}->{ $arr[0] }}, $line;

        }

        close $fh;
        undef $fh;
    }

    my %union;
    for my $file ( keys %ips ) {

        for my $ip ( keys %{ $ips{$file} } ) {
            $union{ $ip } ||= 0;
            $union{ $ip } += 1;
        }
    }

    my @union;
    for ( keys %union ) {
    	push @union, $_ if $union{$_} == @files;
    }

    open my $fh, '>', $OUT or die $!;
    for my $file ( keys %data ) {
    	for my $ip ( @union ) {
    		say $fh join ';', $file, @{ $data{$file}->{$ip} };
    	}
    }
    close $fh;
    undef $fh;
}

__END__

