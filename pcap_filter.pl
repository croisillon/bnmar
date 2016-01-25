#!/usr/bin/perl

use warnings;
use strict;
use Net::Pcap;
use Socket qw(inet_aton);
use Data::Dumper;
use File::Temp qw/ tempfile tempdir /;
use Time::Piece ':override';
use PP;

select STDOUT;
$| = 1;

use constant {
    NET_MASK      => unpack( 'N', Socket::inet_aton("255.255.255.0") ),
    NET_ADDR      => unpack( 'N', Socket::inet_aton("192.168.2.0") ),
    PCAP_IN       => 'netdump.pcap',
    PCAP_OUT      => 'filtered.pcap',
    TEMP_FILE_EXT => '.pcap',
    TEMP_FILE_DIR => '/tmp',
};

use constant VERBOSE => 0;

my ( %cache, %sessions, %journal );

BEGIN {

# Open the file with the converted number in the IP address of the domain (TOP 100)
# http://www.similarweb.com/country/russian_federation
    open( TABLE, '<', 'domains.digits.table' ) or die $!;
    while (<TABLE>) { $cache{$_} = 1; }
    close TABLE;

}

sub main {
    my ( $pcap, $packet, $errbuf, %header, $p, $pcap_dump);
    my ( $src_ip, $dst_ip, $key, $flags, $src_port, $dst_port );

    $pcap = Net::Pcap::pcap_open_offline( PCAP_IN, \$errbuf )
        or die("error reading pcap file: $errbuf");

    $pcap_dump = Net::Pcap::pcap_dump_open( $pcap, PCAP_OUT );
	
    print localtime(time)->hms." - Start parsing file " . PCAP_IN . "\n";
    while ( $packet = Net::Pcap::pcap_next( $pcap, \%header ) ) {

        $p = &PP::parse_packet( $packet, \%header );

        # Only IPv4
        next unless $p->{'eth'}->{'type'} == ETH_TYPE_IP;

        # Only TCP
        next unless $p->{'ip'}->{'proto'} == IP_PROTO_TCP;

        $src_ip = &compare( $p->{'ip'}->{'src'} );
        $dst_ip = &compare( $p->{'ip'}->{'dst'} );

        # If the source and destination address is a local area network
        next if ( $src_ip && $dst_ip );

        # If the request does not belong to any study network
        next if ( !$src_ip && !$dst_ip );

# The source is not from the home network and the receiver in the home network
        if ( !$src_ip && $dst_ip ) {

            # To change address locations for future key
            ( $src_ip, $dst_ip ) = @{ $p->{'ip'} }{qw/dst src/};
            ( $src_port, $dst_port )
                = @{ $p->{'tcp'} }{qw/dst_port src_port/};
        }
        else {
            ( $src_ip, $dst_ip ) = @{ $p->{'ip'} }{qw/src dst/};
            ( $src_port, $dst_port )
                = @{ $p->{'tcp'} }{qw/src_port dst_port/};
        }

        # Search address in the list of top 100
        next if defined $cache{$dst_ip};

        $key = $src_ip . $dst_ip . $src_port . $dst_port;

        $flags = $p->{'tcp'}->{'flags'};

        if ( $flags == TCP_FLAG_SYN ) {
            $journal{$key}->{'SYN'} = 1;
            $journal{$key}->{'FIN'} = 0;
            $journal{$key}->{'ACK'} = 0;
        }

        # SYN
        # Request to start session
        # Now we can create a file and write to all packages
        # https://tools.ietf.org/html/rfc793#page-30
        if ( defined $journal{$key}->{'SYN'} ) {

            # Create a new temporary file
            unless ( ref $journal{$key}->{'FH'} eq ref $pcap_dump ) {

                # Filename
                $journal{$key}->{'FN'} = &file_path($key);

                # Filehandle
                $journal{$key}->{'FH'} = Net::Pcap::pcap_dump_open( $pcap,
                    $journal{$key}->{'FN'} );
            }

            # Recording package to a temporary file
            Net::Pcap::pcap_dump( $journal{$key}->{'FH'}, \%header, $packet );
            Net::Pcap::pcap_dump_flush( $journal{$key}->{'FH'} );

            # ACK, SYN
            # https://tools.ietf.org/html/rfc793#page-30
            $journal{$key}->{'SYN'} = 2
                if $flags == ( TCP_FLAG_ACK + TCP_FLAG_SYN );

            # ACK, FIN or FIN, PSH, ACK
            # https://tools.ietf.org/html/rfc793#page-39
            if (   $flags == ( TCP_FLAG_FIN + TCP_FLAG_ACK )
                || $flags == ( TCP_FLAG_PSH + TCP_FLAG_FIN + TCP_FLAG_ACK ) )
            {
                $journal{$key}->{'FIN'} = 1 if !$journal{$key}->{'FIN'};
                $journal{$key}->{'FIN'} = 2 if $journal{$key}->{'FIN'} == 1;
            }
            elsif ( $journal{$key}->{'FIN'} > 0 ) {

                # Collect the remaining packages
                # Closure type compounds 1,2
                # https://tools.ietf.org/html/rfc793#page-39

                ++$journal{$key}->{'ACK'};
            }

        }
        else {
            undef $journal{$key};
            delete $journal{$key};

        }

        if ( defined $journal{$key}->{'SYN'} ) {

            $flags
                = $journal{$key}->{'SYN'}
                + $journal{$key}->{'FIN'}
                + $journal{$key}->{'ACK'};

            if ( $flags == 6 ) {

                # A floating dump in the main file
                &save( $journal{$key}, $pcap_dump );
            }
        }

        undef %header;
        $src_ip = $dst_ip = $key = $flags = $packet = undef;
    }    # .while
    print localtime(time)->hms . " - Parsing has been completed\n";

    Net::Pcap::pcap_dump_close($pcap_dump);
    Net::Pcap::pcap_close($pcap);

    # Garbage collection
    print "Garbage collection\n";
    unlink glob &file_path('*');

    sleep(2);
}

# Checks the address of the belonging network
sub compare {
    return undef unless $_[0];
    return ( ( $_[0] & NET_MASK ) == NET_ADDR );
}

sub file_path {
    return TEMP_FILE_DIR . "/" . (shift) . TEMP_FILE_EXT;
}

sub save {
    my $journal   = shift;
    my $pcap_dump = shift;

    Net::Pcap::pcap_dump_close( $journal->{'FH'} );
    $journal->{'FH'} = undef;

    &move_to( $journal->{'FN'}, $pcap_dump );
    $journal->{'FN'} = undef;
    unlink glob $journal->{'FN'};

    $journal = undef;

    return 0;
}

sub move_to {
    my $fn   = shift;    # $journal{$key}->{'FN'}
    my $dump = shift;    # $pcap_dump

    my $i = 0;

    my ( $pcap, $errbuf, $packet, %header );

    $pcap = Net::Pcap::pcap_open_offline( $fn, \$errbuf );

    while ( $packet = Net::Pcap::pcap_next( $pcap, \%header ) ) {
        ++$i;
        Net::Pcap::pcap_dump( $dump, \%header, $packet );
        Net::Pcap::pcap_dump_flush($dump);
    }
    print "Recorded in the main file packages -> $i \n" if VERBOSE;

    Net::Pcap::pcap_close($pcap);

    return 0;
}

&main();

__END__

