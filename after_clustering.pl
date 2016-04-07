#!/usr/bin/perl

use feature ':5.10';
use Data::Dumper;
use Net::DNS;
use Getopt::Long 'HelpMessage';

$| = 1;

my ( $in, $out );

GetOptions(
    'in=s'   => \$in,
    'out=s'    => \$out,
    'help'     => sub { HelpMessage(0) }
) or HelpMessage(1);

my $whois = '/usr/bin/whois';

sub whois ($) {
    my $ip = shift;

    my ($fh, @answ);
    open $fh, "-|", "$whois $ip" or die $!;
    @answ = <$fh>;

    my $str = join "\n", @answ;
    $str =~ m/netname:\s+(\w+)\-?/i;
    $str = $1;
    $str =~ s/\W//;

    return lc $str;
}

my ( $resolver, $fh, %vars, $reply, $i, @trash, $copy, $result );

$resolver = Net::DNS::Resolver->new(
    nameservers => [ '8.8.8.8', '8.8.4.4', '77.88.8.8', '77.88.8.1' ] 
);

open $fh,  '<', $in or die $!;
open $nfh, '>', $out or die $!;

my (%cache, $str);

$i = 0;
while ( $line = <$fh> ) {

    $copy = $line;

    # Отбрасываем заголовок
    unless ($i) {
        $line =~ s/\n//;
        print $nfh $line.',"resolv","whois"'."\n";
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
                $cache{ $vars{'dst'} }->{'resolv'} = '"' . $rec->ptrdname . '"';
            }
        }
        else {
            $cache{ $vars{'dst'} }->{'resolv'} = '"NA"';
        }

        $cache{ $vars{'dst'} }->{'whois'} = &whois( $vars{'dst'} );

        print ' [found] ';
    }
    else {
        print ' [from cache] ';
    }

    print $cache{ $vars{'dst'} }->{'resolv'} .' => '. $cache{ $vars{'dst'} }->{'whois'} . "\n";

    $copy =~ s/\n$//;
    print $nfh join( ',', $copy, $cache{ $vars{'dst'} }->{'resolv'}, $cache{ $vars{'dst'} }->{'whois'} ) . "\n";

}

close $fh;

__END__
