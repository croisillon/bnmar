#!/usr/bin/perl

use warnings;
use strict;
use Net::Pcap;
use Socket qw(inet_aton);
use Data::Dumper;
use File::Temp qw/ tempfile tempdir /;
use Time::Piece ':override';
use PP;
use feature ':5.10';
use Getopt::Long 'HelpMessage';
use File::Spec;

my ( $PCAP_IN, $PCAP_OUT, $VERBOSE );

$VERBOSE = 1;
GetOptions(
    'file=s'  => \$PCAP_IN,
    'out=s'   => \$PCAP_OUT,
    'verbose' => \$VERBOSE
) or HelpMessage(1);

die "$0 requires the input filename argument (--file)\n" unless $PCAP_IN;

# die "$0 requires the output filename argument (--out)\n" unless $PCAP_OUT;

$| = 1;

use constant {
    NET_MASK      => unpack( 'N', Socket::inet_aton("255.255.255.0") ),
    NET_ADDR      => unpack( 'N', Socket::inet_aton("192.168.2.0") ),
    PCAP_IN       => 'netdump.pcap',
    PCAP_OUT      => 'filtered.pcap',
    TEMP_FILE_EXT => '.pcap',
    TEMP_FILE_DIR => '/tmp',
};

my ( %store, %dict );

my $errbuf;
my $pcap = Net::Pcap::pcap_open_offline( $PCAP_IN, \$errbuf )
    or die("error reading pcap file: $errbuf");

# $pcap_dump = Net::Pcap::pcap_dump_open( $pcap, $PCAP_OUT );

say sprintf( '%s - Start parsing file %s', localtime(time)->hms, $PCAP_IN );

my ( $pack, $packet, %header );
my ( $flags, $src, $dst, $key, $flow, $data );
while ( $packet = Net::Pcap::pcap_next( $pcap, \%header ) ) {
    $pack = &PP::parse_packet( $packet, \%header );
    $flow = $data = $src = $dst = undef;

    # Only IPv4
    next unless is_ipv4_packet($pack);

    # Only TCP
    next unless is_tcp_proto($pack);

    # (\@, \@)
    ( $src, $dst ) = get_direction($pack);

    # \%
    $flow = find_flow( $src, $dst );

    $flags = $pack->{'tcp'}->{'flags'};

    # https://tools.ietf.org/html/rfc793#page-30
    if ( $flags == TCP_FLAG_SYN ) {

        $flow = create_flow( $src, $dst );
        $flow = init_flow( $pack, $flow );

        say sprintf( 'Flow %s has been detected',
            ( _concat_addr($src) . ' to ' . _concat_addr($dst) ) )
            if $VERBOSE;

        calculate( $pack, $flow );
        next;
    }

    next unless $flow;

    if ( check_flag( $flags, TCP_FLAG_SYN + TCP_FLAG_ACK ) ) {

        # https://tools.ietf.org/html/rfc793#page-30
        $flow->{'_syn_'} = 2;

        calculate( $pack, $flow );
    }
    elsif ( check_flag( $flags, TCP_FLAG_FIN + TCP_FLAG_ACK ) ) {

        # https://tools.ietf.org/html/rfc793#page-39
        $flow->{'_fin_'} = 1 if !$flow->{'_fin_'};
        $flow->{'_fin_'} = 2 if $flow->{'_fin_'};

        calculate( $pack, $flow );

    }
    elsif ( check_flag( $flags, TCP_FLAG_ACK ) ) {

        # https://tools.ietf.org/html/rfc793#page-39
        if ( $flow->{'_fin_'} ) {
            $flow->{'_ack_'} += 1;
            calculate( $pack, $flow );
        }
        else {
            calculate( $pack, $flow );
        }

        if ( $flow->{'_ack_'} == 2 ) {
            $flags = $flow->{'_syn_'} + $flow->{'_fin_'} + $flow->{'_ack_'};

            if ( $flags == 6 ) {
                last;
            }
        }
    }

}    # .while

say Dumper \%store;

# 0.243
# say $flow->{'time'}->[-2] - $flow->{'time'}->[0];
# say $flow->{'time'}->[-1] - $flow->{'time'}->[1];
# say $flow->{'time'}->[-1] - $flow->{'time'}->[2];
# say $flow->{'time'}->[-1] - $flow->{'time'}->[0];
# say $flow->{'time'}->[-1], ' - ', $flow->{'time'}->[2];

# # # Durat
# # my $t = $times[-1] - $times[0];
# # say sprintf("%s", substr($t,0, 5));

say sprintf( '%s - Parsing has been completed', localtime(time)->hms );

# Net::Pcap::pcap_dump_close($pcap_dump);
# Net::Pcap::pcap_close($pcap);

# Garbage collection
print "Garbage collection\n";

# unlink glob &file_path('*');

sub calculate {
    my ( $pack, $flow ) = @_;

    my $data = get_direct_data( get_direction($pack) );

    push @{ $flow->{'time'} }, join '.', @{ $pack->{'hdr'} }{qw/tv_sec tv_usec/};
    push @{ $data->{'time'} }, join '.', @{ $pack->{'hdr'} }{qw/tv_sec tv_usec/};

    $flow->{'packets'} += 1;
    $data->{'packets'} += 1;

    my $flow_len = $pack->{'hdr'}->{'len'};
    $flow->{'bytes'} += $flow_len;
    $data->{'bytes'} += $flow_len;
}

sub init_flow {
    my ( $pack, $flow ) = @_;

    $flow->{'_syn_'} = 1;
    $flow->{'_fin_'} = 0;
    $flow->{'_ack_'} = 0;

    $flow->{'time'}    = [];
    $flow->{'packets'} = 0;
    $flow->{'bytes'}   = 0;
    $flow->{'flags'}   = 'ESTABLISHED';

    $flow->{'proto'} = $pack->{'ip'}->{'proto'};

    ( $flow->{'src'}, $flow->{'dst'} ) = get_direction($pack);

    return $flow;
}

sub init_subflow {
    my ($data) = @_;

    $data->{'time'}    = [];
    $data->{'packets'} = 0;
    $data->{'bytes'}   = 0;

    return $data;
}

sub is_ipv4_packet { shift->{'eth'}->{'type'} == ETH_TYPE_IP }

sub is_tcp_proto { shift->{'ip'}->{'proto'} == IP_PROTO_TCP }

sub get_direction {
    my ($pack) = @_;

    my ( $ip1,   $ip2 )   = @{ $pack->{'ip'} }{qw/src dst/};
    my ( $port1, $port2 ) = @{ $pack->{'tcp'} }{qw/src_port dst_port/};

    my $addr1 = [ $ip1, $port1 ];
    my $addr2 = [ $ip2, $port2 ];

    return $addr1, $addr2;
}

sub get_dictionary_path {
    $dict{ _concat_addr( @{ $_[0] } ) }->{ _concat_addr( @{ $_[1] } ) } ||= {};
}

sub check_flag { ( $_[0] & $_[1] ) == $_[1] }

sub unique_key { @_ = ( '_', @_ ); goto &_concat; }

sub _concat_addr { @_ = ( ':', @_ ); goto &_concat; }

sub _concat {
    my ($sep) = @_;

    $sep = length $sep == 1 ? shift @_ : '';

    my @args;
    for (@_) {
        if ( ref $_ eq 'ARRAY' ) {
            push @args, @{$_};
        }
        else {
            push @args, $_;
        }
    }

    my $i      = @args;
    my $format = '';
    while ( $i-- ) {
        $format .= '%s';
        $format .= $sep if $i;
    }

    return sprintf( $format, @args );
}

use constant {
    OUT_FLOW => '_OUT',
    IN_FLOW  => '_IN',
};

sub create_flow {
    my ( $addr1, $addr2 ) = @_;

    my $key = unique_key( $addr1, $addr2 );

    # Computer to Internet (Request to server)
    my $dict_path = get_dictionary_path( $addr1, $addr2 );
    $dict_path->{'key'}    = $key;
    $dict_path->{'direct'} = OUT_FLOW;

    # Internet to Computer (Answer from server)
    $dict_path = get_dictionary_path( $addr2, $addr1 );
    $dict_path->{'key'}    = $key;
    $dict_path->{'direct'} = IN_FLOW;

    # Делим большой поток на два маленьких
    $store{$key} = {
        &IN_FLOW => {
            'src' => $addr2,
            'dst' => $addr1
        },
        &OUT_FLOW => {
            'src' => $addr1,
            'dst' => $addr2
        }
    };

    $store{$key}->{$_} = init_subflow( $store{$key}->{$_} ) for ( &OUT_FLOW, &IN_FLOW );

    return $store{$key};
}

sub find_flow {
    my ( $addr1, $addr2 ) = @_;

    my $dict_path = get_dictionary_path( $addr1, $addr2 );

    return undef unless %{$dict_path};

    return $store{ $dict_path->{'key'} } if $dict_path->{'key'};

    return undef;
}

sub get_direct_data {
    my ( $addr1, $addr2 ) = @_;

    my $key = unique_key( $addr1, $addr2 );
    my $dict_path = get_dictionary_path( $addr1, $addr2 );
    my $direct = $dict_path->{'direct'};

    return $store{$key}->{$direct} if $direct;
}

__END__

