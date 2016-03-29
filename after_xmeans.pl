#!/usr/bin/perl

use feature ':5.10';
use Data::Dumper;
use Net::DNS;

$| = 1;

my ( $resolver, $fh, %vars, $reply, $i, @trash, $copy, $result );

$resolver = Net::DNS::Resolver->new(
    nameservers => [ '8.8.8.8', '8.8.4.4', '77.88.8.8', '77.88.8.1' ] );

open $fh,  '<', './xmeans2_clustering.csv' or die $!;
open $nfh, '>', './xmeans_mod.csv'         or die $!;

my %cache;

$i = 0;
while ( $line = <$fh> ) {

    $copy = $line;

    # Отбрасываем заголовок
    unless ($i) {
        print $nfh $line;
        print "\n";
        ++$i;
        next;
    }

    # Убираем лишние знаки
    $line =~ s/\n$//;
    $line =~ s/^\"|\"$//g;
    $line =~ s/\s*//g;

    ( $vars, $vars{'src'}, $vars{'dst'}, @trash ) = split /\",(?:\")?/, $line;

    print 'Lookup: ' . $vars{'dst'};

    unless ( $cache{ $vars{'dst'} } ) {

        $reply = $resolver->search( $vars{'dst'} );

        if ( defined $reply ) {
            foreach my $rec ( $reply->answer ) {
                next unless $rec->type eq "PTR";
                $cache{ $vars{'dst'} } = '"' . $rec->ptrdname . '"';
            }
        }
        else {
            $cache{ $vars{'dst'} } = '"NA"';
        }

        print ' [found] ';
    }
    else {
        print ' [from cache] ';
    }

    print $cache{ $vars{'dst'} } . "\n";

    $copy =~ s/\n$//;
    print $nfh join( ',', $copy, $cache{ $vars{'dst'} } ) . "\n";

}

close $fh;

__END__
