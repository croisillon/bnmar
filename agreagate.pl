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

my $args = {@ARGV};

unless ( scalar @ARGV ) {
    print "For example: \n";
    print './agregate.pl --file traffic.csv --out vector.csv';
    print "\n";
    exit;
}

my $FILE_IN = $args->{'--file'};
my $FILE_OUT = $args->{'--out'} || (localtime)->epoch.'_vector.csv';

sub main {
    my ( %journal, $line, $key, %vars, $i, $fh, %keys, @keys );

    open $fh, '<', $FILE_IN or die $!;

    my ( $t, $src, $srcp, $dst, $dstp, $ppf, $bpp, $bps );

    $i = 0;
    while ( $line = <$fh> ) {

        # Отбрасываем заголовок
        if ( !$i ) { ++$i; next; }

        # Убираем лишние знаки
        $line =~ s/\n$//;
        $line =~ s/\"//g;

        ( $t, $src, $srcp, $dst, $dstp, $ppf, $bpp, $bps ) = split ',', $line;

        # Ключ из ip_src + ip_dst + port_dst
        $key = $src . $dst . $dstp;

        # Сохраняем ключ, если такого нет
        unless ( defined $keys{$key} ) {
            push @keys, $key;
            $keys{$key} = 1;
        }

        # Сохраняем время как ключ
        $vars{$t} = 1 if $t;

        # Считаем пакеты
        $journal{$key}->{'i'} ||= 0;
        $journal{$key}->{'i'} += 1;

        # Сохраняем данные
        $journal{$key}->{'data'}->{'src'}  = $src;
        $journal{$key}->{'data'}->{'dst'}  = $dst;
        $journal{$key}->{'data'}->{'dstp'} = $dstp;

        $journal{$key}->{'data'}->{'t'}->{$t}
            = $journal{$key}->{'data'}->{'t'}->{$t}
            ? ++$journal{$key}->{'data'}->{'t'}->{$t}
            : 1;

        push @{ $journal{$key}->{'data'}->{'ppf'} }, $ppf;
        push @{ $journal{$key}->{'data'}->{'bpp'} }, $bpp;
        push @{ $journal{$key}->{'data'}->{'bps'} }, $bps;
    }
    close $fh;
    undef $fh;

    open $fh, '>', $FILE_OUT;
    print $fh "\""
        . ( join "\", \"", qw/src_ip dst_ip dst_port fph ppf bpp bps/ )
        . "\"\n";

    while ( $key = shift @keys ) {

        ( $src, $dst, $dstp, $ppf, $bpp, $bps, $t )
            = @{ $journal{$key}->{'data'} }{qw/src dst dstp ppf bpp bps t/};

        my @k   = sort keys %vars;
        my $fph = [];
        map {
            next unless $_;
            push @$fph, ( $t->{$_} || 0 );
        } @k;

        $ppf = join ',', @$ppf;
        $bpp = join ',', @$bpp;
        $bps = join ',', @$bps;
        $fph = join ',', @$fph;

        print $fh "\""
            . ( join( "\", \"", $src, $dst, $dstp, $fph, $ppf, $bpp, $bps ) )
            . "\"\n";
    }
    
    close $fh;
    undef $fh;

}

&main();

__END__


