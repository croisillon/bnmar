#!/usr/bin/perl

use strict;
use feature ':5.10';
use Data::Dumper;
use Net::DNS;
use Getopt::Long 'HelpMessage';

$| = 1;

my ( $in, $out, $column, $nodb, $headline );
my $VERBOSE = 1;
$column = undef;
GetOptions(
    'in=s'     => \$in,
    'out=s'    => \$out,
    'column=i' => \$column,
    'nodb'     => \$nodb,
    'headline' => \$headline,
    'help'     => sub { HelpMessage(0) }
) or HelpMessage(1);

HelpMessage(1) unless $column;
$out = 'out.whois.csv' unless $out;

my $whois    = '/usr/bin/whois';
my $whois_db = './whois.db';

sub whois ($) {
    my $ip = shift;

    my ( $fh, @answ );
    open $fh, "-|", "$whois $ip" or die $!;
    @answ = <$fh>;

    my $str = join "\n", @answ;
    $str =~ m/netname:\s+(.+)/i;
    $str = lc $1;

    # Delete all non-alphabetic symbols
    $str =~ s/[[:^alpha:]]//g;

    return $str;
}

sub read_db_in_cache {
    my $cache = shift;
    my $str;

    ( !-e $whois_db ) && return;

    open FH, '<', $whois_db or die $!;

    while ( $str = <FH> ) {

        $str =~ s/\n$//;
        $str = [ split ';', $str ];

        $cache->{ $str->[0] . '' }->{'whois'}  = $str->[1];
        $cache->{ $str->[0] . '' }->{'resolv'} = $str->[2];

    }

    close FH;

    return;
}

sub write_db_from_cache {
    my $cache = shift;
    my ( @keys, $ws, $rs );

    open FH, '>', $whois_db or die $!;

    @keys = keys %$cache;
    for (@keys) {

        # Key may be undefined
        next unless defined $_;

        ( $ws, $rs ) = @{ $cache->{$_} }{qw/ whois resolv /};
        $_ = join( ";", $_, $ws, $rs );

        print FH $_ . "\n";
    }
    close FH;

    return;
}

# INIT
my ( %cache, $resolver, $ifh, $ofh );

if ( !$nodb ) {
    say 'Reading database to cache...';
    &read_db_in_cache( \%cache );
}

$resolver = Net::DNS::Resolver->new(
    nameservers => [ '8.8.8.8', '8.8.4.4', '77.88.8.8', '77.88.8.1' ] );

open $ifh, '<', $in  or die $!;
open $ofh, '>', $out or die $!;

# MAIN
my ( $status, $line, $copy, $ip, $i, @rows, $reply );

if ($headline) {
    $headline = readline($ifh);
    chomp $headline;
    say $ofh $headline . ';"resolv";"whois"';
}

$i = 0;
while ( $line = <$ifh> ) {
    chomp $line;

    $copy = $line;

    # Parse .csv file
    $line =~ s/"//g;

    @rows = split ';', $line;

    $ip = $rows[ $column - 1 ];

    print sprintf( "Lookup: %-16s ", $ip ) if $VERBOSE;

    if ( !$nodb && $cache{$ip} ) {
        $status = '[CACHE]';
    }
    else {

        $reply = $resolver->search($ip);

        if ( defined $reply ) {
            foreach my $rec ( $reply->answer ) {
                next unless $rec->type eq "PTR";
                $cache{$ip}->{'resolv'} = '"' . $rec->ptrdname . '"';
            }
        }
        else {
            $cache{$ip}->{'resolv'} = '"NA"';
        }

        $cache{$ip}->{'whois'} = &whois($ip);

        $status = '[DNS]';
    }

    say sprintf(
        "%-8s WHOIS: %-25s \t DNS RESOLVE: %s",
        $status,
        $cache{$ip}->{'whois'},
        $cache{$ip}->{'resolv'}
    ) if $VERBOSE;

    print $ofh
        join( ';', $copy, $cache{$ip}->{'resolv'}, q{"}.$cache{$ip}->{'whois'}.q{"} )
        . "\n";

}

close $ifh;

say 'Dumping cache to database file...';
&write_db_from_cache( \%cache );

say 'Done...';
say "The program ran for ", time() - $^T, " seconds";

__END__

=head1 NAME

    DNS Resolver for *.csv files

=head1 VERSION

Version 1.05

=head1 SYNOPSIS

 whois_csv.pl [КЛЮЧ]

 -i, --in          Входной файл
 -o, --out         Выходной файл (по умолчанию: out.whois.csv)
 -c, --column      Номер колонки в которой содержится IP адрес (> 0)
     --nodb        Не использовать кэш-базу при определении
     --headline    Указывает на то что первая строка в файле заголовок
     --help        Показать эту справку и выйти

=head2 Примеры

    whois_csv --in some_in_file.csv --out some_out_file.csv --column 3
    whois_csv --in some_in_file.csv --out some_out_file.csv --column 1 --nodb --headline
    whois_csv --in some_in_file.csv --column 1 --headline

=head1 DESCRIPTION

    Исользуюя whois определяет принадлежность IP адреса

=head1 AUTHOR

Denis Lavrov (C<diolavr@gmail.com>)

=cut
