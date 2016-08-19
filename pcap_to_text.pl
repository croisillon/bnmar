#!/usr/bin/perl

use warnings;
use strict;
use Net::Pcap;
use IO::File;
use Socket qw(inet_aton);
use Data::Dumper;
use File::Temp qw/ tempfile tempdir /;
use Time::Piece ':override';
use PP;
use feature ':5.10';
use Getopt::Long 'HelpMessage';
use File::Spec;

local $ENV{TZ} = 'UTC-2';

my ( $PCAP_IN, $PCAP_OUT, $PCAP_OUT_TMP, $VERBOSE );

$VERBOSE = 1;
GetOptions(
    'file=s'  => \$PCAP_IN,
    'out=s'   => \$PCAP_OUT,
    'verbose' => \$VERBOSE
) or HelpMessage(1);

die "$0 requires the input filename argument (--file)\n" unless $PCAP_IN;
die "$0 requires the output filename argument (--out)\n" unless $PCAP_OUT;

$| = 1;

use constant {
    NET_MASK => unpack( 'N', Socket::inet_aton("255.255.255.0") ),
    NET_ADDR => unpack( 'N', Socket::inet_aton("192.168.2.0") ),
    OUT_FLOW => '_OUT',
    IN_FLOW  => '_IN',
    TEMP_EXT => '.tmp'
};

$PCAP_OUT_TMP = "$PCAP_OUT".TEMP_EXT;

my ( %store, %keys );

my $errbuf;
my $pcap = Net::Pcap::pcap_open_offline( $PCAP_IN, \$errbuf )
    or die("error reading pcap file: $errbuf");

my $output;
open $output, '>', $PCAP_OUT_TMP or die $!;
file_output_header($output);

say sprintf( '%s - Start parsing file %s', localtime(time)->hms, $PCAP_IN );

my ( $pack, $packet, %header );
my ( $flags, $src, $dst, $flow, $direct );
while ( $packet = Net::Pcap::pcap_next( $pcap, \%header ) ) {
    $pack = &PP::parse_packet( $packet, \%header );
    $flow = $direct = $src = $dst = undef;

    # Only IPv4
    next unless is_ipv4_packet($pack);

    # Only TCP
    next unless is_tcp_proto($pack);

    # \@
    $direct = get_direction($pack);

    # \%
    $flow = find_flow(@$direct);

    # $
    $flags = $pack->{'tcp'}->{'flags'};

    # https://tools.ietf.org/html/rfc793#page-30
    if ( $flags == TCP_FLAG_SYN ) {

        $flow = create_flow(@$direct);

        $flow->{'proto'} = $pack->{'ip'}->{'proto'};

        $flow->{'ip_src'} = _addr_port( @{ $direct->[0] } );
        $flow->{'ip_dst'} = _addr_port( @{ $direct->[1] } );

        $flow->{'_src'}    = _concat_addr( $direct->[0] );
        $flow->{'_dst'}    = _concat_addr( $direct->[1] );
        $flow->{'_direct'} = $direct;

        $flow = init_flow($flow);

        _verbose( 'Flow %s has been (detected)', _flow_name($flow) );

        calc_flow($pack);
        next;
    }

    next unless $flow;

    if ( check_flag( $flags, TCP_FLAG_SYN + TCP_FLAG_ACK ) ) {

        # https://tools.ietf.org/html/rfc793#page-30
        $flow->{'_syn_'} = 2;

        calc_flow($pack);
    }
    elsif ( check_flag( $flags, TCP_FLAG_FIN + TCP_FLAG_ACK ) ) {

        # https://tools.ietf.org/html/rfc793#page-39
        $flow->{'_fin_'} = 1 if !$flow->{'_fin_'};
        $flow->{'_fin_'} = 2 if $flow->{'_fin_'};

        calc_flow($pack);
    }
    elsif ( check_flag( $flags, TCP_FLAG_ACK ) ) {

        # https://tools.ietf.org/html/rfc793#page-39
        if ( $flow->{'_fin_'} ) {
            $flow->{'_ack_'} += 1;
            calc_flow($pack);
        }
        else {
            calc_flow($pack);
        }

        if ( $flow->{'_ack_'} == 2 ) {
            $flags = $flow->{'_syn_'} + $flow->{'_fin_'} + $flow->{'_ack_'};

            if ( $flags == 6 ) {
                _verbose( 'Flow %s has been [complited]', _flow_name($flow) );
                save_flow($flow);
            }
        }
    }

}    # .while

%store = ();
%keys  = ();

say sprintf( '%s - Parsing has been completed', localtime(time)->hms );

close $output;

Net::Pcap::pcap_close($pcap);

system("sort -k2 -n $PCAP_OUT_TMP > $PCAP_OUT");
unlink $PCAP_OUT_TMP;

sub file_output_header {
    my $fh = shift;
    my @header = (
        "Date flow start\t",
        'Durat', 'Prot', 'Src IP Addr:Port',
        '', 'Dst IP Addr:Port',
        'Flags', 'Tos', 'Packets', 'Bytes', 'Flows', 'Label', 'Labels'
    );
    
    my $str = join "\t", @header;
    $str .= "\n";
    syswrite $fh, $str, length $str or die $!;
}

sub file_output_line {
    my ( $fh, $flow, $subflow ) = @_;

    my @data = (
        [ '%s',   _dt( $subflow->{'time'}->[0] ) ],
        [ '%s',   _durat( $subflow->{'time'} ) ],
        [ '%03x', $flow->{'proto'} ],
        [ '%s',   _addr_port( @{ $subflow->{'src'} } ) ],
        [ '%s',   '->' ],
        [ '%s',   _addr_port( @{ $subflow->{'dst'} } ) ],
        [ '%s',   $flow->{'flags'} ],
        [ '%0d',  0 ],
        [ '%d',   $subflow->{'packets'} ],
        [ '%d',   $subflow->{'bytes'} ],
        [ '%d',   1 ],
        [ '%s',   'LABEL' ],
        [ '%s',   'LABELS' ]
    );

    my $format = [];
    my @args;

    for (@data) {
        push @$format, $_->[0];
        push @args,    $_->[1];
    }

    _verbose( 'Flow %s has been <saved> [Packets: %d, Bytes: %d]',
        _flow_name($flow), $subflow->{'packets'}, $subflow->{'bytes'} );

    $format = join "\t", @$format;
    my $str = sprintf( $format . "\n", @args );

    syswrite $fh, $str, length $str or die $!;
}

sub save_flow {
    my ($flow) = @_;

    file_output_line( $output, $flow, $flow->{&IN_FLOW} );
    # file_output_line( $output, $flow, $flow->{&OUT_FLOW} );

    my $key = delete_path( @{ $flow->{'_direct'} } );

    $store{$key} = {};
    delete $store{$key};

}

sub _dt {
    @_ = split /\./, $_[0];
    localtime( $_[0] )->datetime( 'T' => ' ' ) . '.' . substr( $_[1], 0, 3 );
}
sub _durat { 
    my $result = sprintf('%d.%06d', split /\./, $_[0]->[-1] ) -  
    sprintf('%d.%06d', split /\./, $_[0]->[0] );
    return substr( $result, 0, 5 );
}
sub _addr_port { PP::toDotQuad(shift) . ':' . (shift) }

sub _verbose { say sprintf( shift, @_ ) if $VERBOSE }
sub _flow_name { $_[0]->{'ip_src'} . ' to ' . $_[0]->{'ip_dst'} }

sub calc_flow {
    my ($pack) = @_;

    my $data = get_direct_data( get_direction($pack) );

    push @{ $data->{'time'} }, join '.', @{ $pack->{'hdr'} }{qw/tv_sec tv_usec/};

    $data->{'packets'} += 1;

    $data->{'bytes'} += $pack->{'hdr'}->{'len'};

    return undef;
}

sub init_flow {
    my $flow = shift;

    $flow->{'_syn_'} = 1;
    $flow->{'_fin_'} = 0;
    $flow->{'_ack_'} = 0;

    $flow->{'flags'} = 'UAPRSF';

    return $flow;
}

sub init_subflow {
    my $data = shift;

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

    return $addr1, $addr2 if wantarray;
    return [ $addr1, $addr2 ];
}

sub get_path {

    # Получение единого ключа хранилища для двух потоков
    # из пути вида { scr_addr:port }->{ dst_addr:port }
    # Примечание: учтено изменение src и dst
    my $addr = _concat_addr( @{ $_[0] } );
    return $keys{$addr}->{ _concat_addr( @{ $_[1] } ) }
        if $keys{$addr};
}

sub new_path {

    # Возвращает новый путь для хранения ключа хранилища
    return $keys{ _concat_addr( @{ $_[0] } ) }->{ _concat_addr( @{ $_[1] } ) } = {};
}

sub delete_path {
    my $addr1 = _concat_addr( @{ $_[0] } );
    my $addr2 = _concat_addr( @{ $_[1] } );

    my $key = $keys{$addr1}->{$addr2}->{'key'};

    $keys{$addr1} = {};
    delete $keys{$addr1};

    $keys{$addr2} = {};
    delete $keys{$addr2};

    return $key;
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

sub create_flow {
    my (@direct) = @_;

    my $key       = unique_key(@direct);
    my $keys_path = undef;

    # Computer to Internet (Request to server)
    $keys_path             = new_path(@direct);
    $keys_path->{'key'}    = $key;
    $keys_path->{'direct'} = OUT_FLOW;

    # Internet to Computer (Answer from server)
    $keys_path             = new_path( reverse @direct );
    $keys_path->{'key'}    = $key;
    $keys_path->{'direct'} = IN_FLOW;

    # Делим поток на входящий и исходящий
    $store{$key} = {
        &IN_FLOW => {
            'src' => $direct[1],
            'dst' => $direct[0],
        },
        &OUT_FLOW => {
            'src' => $direct[0],
            'dst' => $direct[1]
        }
    };

    # Инициализируем маленькие потоки
    for ( OUT_FLOW, IN_FLOW ) {
        $store{$key}->{$_} = init_subflow( $store{$key}->{$_} );
    }

    return $store{$key};
}

sub find_flow {
    my (@direct) = @_;

    # По адресам найдем в ключах ключ потока
    # По ключу извлекаем поток из хранилища
    my $keys_path = get_path(@direct);

    return undef unless $keys_path;

    return $store{ $keys_path->{'key'} } if $keys_path->{'key'};

    return undef;
}

sub get_direct_data {
    my (@direct) = @_;

    # Определяет по адресам направление потока
    # Возвращает данные для текущего направления потока
    my $keys_path = get_path(@direct);
    my $key       = $keys_path->{'key'};
    my $direct    = $keys_path->{'direct'};

    return $store{$key}->{$direct} if $direct;
}

__END__

