#!/usr/bin/perl

use warnings;
use strict;
use Net::Pcap;
use Data::Dumper;
use Time::Piece ':override';
use Time::Seconds;
use common::sense;
use PP;

select STDOUT;
$| = 1;

use constant REPORT_EXT => '.csv';
use constant REPORT_DIR => 'reports';

sub main {
    my ( %journal, $line, $key, %vars, $i, $fh, @keys );

    open $fh, '<', '58262.csv';

    my ( $t, $src, $srcp, $dst, $dstp, $ppf, $bpp, $bps );

    $i = 0;
    while ( $line = <$fh> ) {
        if ( !$i ) { ++$i; next; }
        $line =~ s/\n$//;
        $line =~ s/\"//g;

        ( $t, $src, $srcp, $dst, $dstp, $ppf, $bpp, $bps ) = split ',', $line;

        $key = $src . $srcp . $dst . $dstp;
        push @keys, $key;

        $journal{$key}->{'i'}
            = $journal{$key}->{'i'} ? $journal{$key}->{'i'} : 0;
        ++$journal{$key}->{'i'};

        $vars{$t} = 1 if $t;

        $journal{$key}->{'t'}              = $t;
        $journal{$key}->{'data'}->{'src'}  = $src;
        $journal{$key}->{'data'}->{'dst'}  = $dst;
        $journal{$key}->{'data'}->{'srcp'} = $srcp;
        $journal{$key}->{'data'}->{'dstp'} = $dstp;

        $journal{$key}->{'data'}->{'t'}->{$t} = $journal{$key}->{'data'}->{'t'}->{$t} ? ++$journal{$key}->{'data'}->{'t'}->{$t} : 1;
        push @{ $journal{$key}->{'data'}->{'ppf'} }, $ppf;
        push @{ $journal{$key}->{'data'}->{'bpp'} }, $bpp;
        push @{ $journal{$key}->{'data'}->{'bps'} }, $bps;
    }
    close $fh;
    undef $fh;

    open $fh, '>', 'vectors.csv';
    print $fh "\""
        . ( join "\", \"", qw/src_ip src_port dst_ip dst_port fph ppf bpp bps/ )
        . "\"\n";

    while ( $key = shift @keys ) {
        ( $src, $srcp, $dst, $dstp )
            = @{ $journal{$key}->{'data'} }{qw/src srcp dst dstp/};
        ( $ppf, $bpp, $bps, $t )
            = @{ $journal{$key}->{'data'} }{qw/ppf bpp bps t/};

        my @k = sort keys %vars;
        my $fph = [];
        map {
            next unless $_;
            push @$fph, ($t->{$_} || 0);
        } @k;

        $ppf = join ',', @$ppf;
        $bpp = join ',', @$bpp;
        $bps = join ',', @$bps;
        $fph = join ',', @$fph;

      print $fh "\""
          . ( join( "\", \"", $src, $srcp, $dst, $dstp, $fph, $ppf, $bpp, $bps ) )
          . "\"\n";

    }

    close $fh;
    undef $fh;

}

&main();

sub report_path {
    return REPORT_DIR . '/' . (shift) . REPORT_EXT;
}

__END__


