#!/usr/bin/perl

use warnings;
use strict;
use Net::Pcap;
use IO::Handle;
use Socket qw(inet_aton);
use Data::Dumper;
use Time::Piece ':override';
use PP;
use feature ':5.10';
use Getopt::Long 'HelpMessage';

STDOUT->autoflush(1);
local $ENV{TZ} = 'UTC-2';

my ( $PCAP_IN, $PCAP_OUT, $PCAP_OUT_TMP, $VERBOSE, $FILTER, @NET );

GetOptions(
    'file=s'    => \$PCAP_IN,
    'out=s'     => \$PCAP_OUT,
    'verbose'   => \$VERBOSE,
    'filter=s'  => \$FILTER,
    'net=s{,}', => \@NET,
    'help'      => sub { HelpMessage(0) }
) or HelpMessage(1);

$FILTER = 'dns/digits.txt' unless $FILTER;
@NET = ( '192.168.0.0', '255.255.0.0' ) unless @NET;
$_ =~ s/,// for @NET;

die "$0 requires the input filename argument (--file)\n" unless -e $PCAP_IN;
die "$0 requires the output filename argument (--out)\n" unless $PCAP_OUT;

my $NET_ADDR = unpack( 'N', inet_aton( $NET[0] ) );
my $NET_MASK = unpack( 'N', inet_aton( $NET[1] ) );

use constant {
    OUT_FLOW => '_OUT',
    IN_FLOW  => '_IN',
    TEMP_EXT => '.tmp'
};

my ( %store, %keys, %ips );

# ---- FILTER IP ADDRESSES
# http://www.similarweb.com/country/russian_federation
open( my $tb, '<', $FILTER ) or die $!;
while (<$tb>) { $ips{$_} = 1; }
close $tb;

# FILTER IP ADDRESSES ----

# ---- OUTPUT FILE
$PCAP_OUT_TMP = "$PCAP_OUT" . TEMP_EXT;
open my $output, '>', $PCAP_OUT_TMP or die $!;
$output->autoflush(1);
file_output_header($output);

# OUTPUT FILE ----

# ---- MAIN CODE
my $errbuf;
my $pcap = Net::Pcap::pcap_open_offline( $PCAP_IN, \$errbuf )
    or die("error reading pcap file: $errbuf");

say sprintf( '%s - Start parsing file %s', localtime(time)->hms, $PCAP_IN );

my ( $pack, $packet, %header );
my ( $flags, $src, $dst, $flow, $direct );
while ( $packet = Net::Pcap::pcap_next( $pcap, \%header ) ) {
    $pack = &PP::parse_packet( $packet, \%header );
    $flow = $direct = $src = $dst = undef;

    # Only IPv4
    next unless is_ipv4_packet($pack);

    # ---- LAN FILTERING
    $src = &is_lan( $pack->{'ip'}->{'src'} );
    $dst = &is_lan( $pack->{'ip'}->{'dst'} );

    # Адреса находятся в локальносй сети
    next if ( $src && $dst );

    # If the request does not belong to any study network
    next if ( !$src && !$dst );

    # LAN FILTERING ----

    # Only TCP
    next unless is_tcp_proto($pack);

    # \@ = [ src_ip, src_port ], [ dst_ip, dst_port ]
    $direct = get_direction($pack);

    # \%
    $flow = find_flow(@$direct);

    # $
    $flags = $pack->{'tcp'}->{'flags'};

    # https://tools.ietf.org/html/rfc793#page-30
    if ( $flags == TCP_FLAG_SYN ) {

        # Адрес источника не локальная сеть
        next unless &is_lan( $direct->[0]->[0] );

        # Фильтрация популярных адресов
        next if defined $ips{ $direct->[1]->[0] };

        $flow = create_flow(@$direct);

        $flow->{'_syn_'} = 1;

        $flow->{'proto'} = 'TCP';
        $flow->{'tos'}   = $pack->{'ip'}->{'tos'};

        $flow->{'ip_src'} = _addr_port( @{ $direct->[0] } );
        $flow->{'ip_dst'} = _addr_port( @{ $direct->[1] } );

        $flow->{'_src'}    = _concat_addr( $direct->[0] );
        $flow->{'_dst'}    = _concat_addr( $direct->[1] );
        $flow->{'_direct'} = $direct;

        _verbose( 'Flow %s has been (detected)', _flow_name($flow) );

        calc_flow($pack);
        next;
    }

    next unless $flow;
    next unless $flow->{'_syn_'};

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

# MAIN CODE ----

system("sort -k2 -n $PCAP_OUT_TMP -o $PCAP_OUT");
unlink $PCAP_OUT_TMP;

# ===============================================================================

# ==== OUTPUT FILE FORMAT

=head2 file_output_header($fh)

B<$fh> - дескриптор файла

=cut

sub file_output_header {
    my $fh     = shift;
    my @header = (
        [ '%-25s', 'Date flow start' ],     # 1
        [ '%-7s',  'Durat' ],               # 2
        [ '%-5s',  'Prot' ],                # 3
        [ '%-21s', 'Src IP Addr:Port' ],    # 4
        [ '%-2s',  '' ],                    # 5
        [ '%-21s', 'Dst IP Addr:Port' ],    # 6
        [ '%-6s',  'Flags' ],               # 7
        [ '%-3s',  'Tos' ],                 # 8
        [ '%-7s',  'Packets' ],             # 9
        [ '%-s',   'Bytes' ]                # 10
    );

    my ( $format, @args );
    $format = [];

    for (@header) {
        push @$format, $_->[0];
        push @args,    $_->[1];
    }
    $format = join "\t", @$format;
    $format .= "\n";

    my $str = sprintf( $format, @args );
    syswrite $fh, $str, length $str or die $!;
}

=head2 file_output_line($fh, $flow, $subflow)

B<$fh> - дескриптор файла
B<$flow> - основной поток, в котором располагается вспомогательная информация 
B<$subflow> - дочерний поток, в котором подсчитываются данные

=cut

sub file_output_line {
    my ( $fh, $flow, $subflow ) = @_;

    my @data = (
        [ '%-25s', _dt( $subflow->{'time'}->[0] ) ],          # 1
        [ '%-7s',  _durat( $subflow->{'time'} ) ],            # 2
        [ '%-5s',  $flow->{'proto'} ],                        # 3
        [ '%-21s', _addr_port( @{ $subflow->{'src'} } ) ],    # 4
        [ '%2s',  '->' ],                                     # 5
        [ '%-21s', _addr_port( @{ $subflow->{'dst'} } ) ],    # 6
        [ '%6s',  $flow->{'flags'} ],                         # 7
        [ '%3d',  $flow->{'tos'} ],                           # 8
        [ '%7d',  $subflow->{'packets'} ],                    # 9
        [ '%d',   $subflow->{'bytes'} ]                       # 10
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

=head2 save_flow($flow)

B<$flow> - основной поток, в котором располагается вспомогательная информация 

=cut

sub save_flow {
    my ($flow) = @_;

    # file_output_line( $output, $flow, $flow->{&IN_FLOW} );

    file_output_line( $output, $flow, $flow->{&OUT_FLOW} );

    clear_flow( @{ $flow->{'_direct'} } );
}

sub _dt {
    @_ = split /\./, $_[0];
    localtime( $_[0] )->datetime( 'T' => ' ' ) . '.' . substr( sprintf( '%06d', $_[1] ), 0, 3 );
}

sub _durat {
    my $result = sprintf( '%d.%06d', split /\./, $_[0]->[-1] )
        - sprintf( '%d.%06d', split /\./, $_[0]->[0] );
    $result =~ s/(\d+\.\d{3}).+/$1/;
    return $result;
}
sub _addr_port { PP::toDotQuad(shift) . ':' . (shift) }

# OUTPUT FILE FORMAT ====

# ==== FLOW CONTROL

=head2 calc_flow($pack)

B<$pack> - обработаные данные о пакете

=cut

sub calc_flow {
    my ($pack) = @_;

    my $keys_path = get_path( get_direction($pack) );
    my $key       = $keys_path->{'key'};
    my $direct    = $keys_path->{'direct'};

    my $data = $store{$key}->{$direct};

    push @{ $data->{'time'} }, join '.', @{ $pack->{'hdr'} }{qw/tv_sec tv_usec/};

    $data->{'packets'} += 1;

    $data->{'bytes'} += $pack->{'hdr'}->{'len'};

    return undef;
}

=head2 init_flow($flow)

B<$flow> - основной поток, в котором располагается вспомогательная информация 

Возвращает инициализированный основной поток

=cut

sub init_flow {
    my $flow = shift;

    $flow->{'_syn_'} = 0;
    $flow->{'_fin_'} = 0;
    $flow->{'_ack_'} = 0;

    $flow->{'flags'} = 'UAPRSF';

    return $flow;
}

=head2 init_subflow($data)

B<$data> - данные направленного потока

Возвращает инициализированные данные направленого потока

=cut

sub init_subflow {
    my $data = shift;

    $data->{'time'}    = [];
    $data->{'packets'} = 0;
    $data->{'bytes'}   = 0;

    return $data;
}

sub _unique_key { @_ = ( '_', @_ ); goto &_concat; }

=head2 create_flow($direct)

B<$direct> - направление потока

const IN_FLOW - направление потока из Интернета к Узлу
const OUT_FLOW - направление потока от Узла в Интернет

Возвращает основной поток с направленными потоками

=cut

sub create_flow {
    my (@direct) = @_;

    my $key       = _unique_key(@direct);
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

    # Инициализируем направленные потоки
    for ( OUT_FLOW, IN_FLOW ) {
        $store{$key}->{$_} = init_subflow( $store{$key}->{$_} );
    }

    return init_flow( $store{$key} );
}

=head2 find_flow($direct)

B<$direct> - направление потока

Возвращает основной поток

=cut

sub find_flow {
    my (@direct) = @_;

    # По адресам найдем в ключах ключ потока
    # По ключу извлекаем поток из хранилища
    my $keys_path = get_path(@direct);

    return undef unless $keys_path;

    return $store{ $keys_path->{'key'} } if $keys_path->{'key'};

    return undef;
}

sub clear_flow {
    my (@direct) = @_;

    my $keys_path = get_path(@direct);

    say Dumper $keys_path;

    say Dumper $store{ $keys_path->{'key'} };
    $store{ $keys_path->{'key'} } = undef;

    delete_path(@direct);
}

# FLOW CONTROL ====

# ==== KEYS CONTROL

=head2 find_flow($direct)

B<$direct> - направление потока

Возвращает ключ для хранилища %store и направление потока
{
    key => '....',
    direct => IN, OUT (одно из направлений)
}

=cut

sub get_path {

    # Получение единого ключа хранилища для двух потоков
    # из пути вида { scr_addr:port }->{ dst_addr:port }
    # Примечание: учтено изменение src и dst
    my $addr = _concat_addr( @{ $_[0] } );
    return $keys{$addr}->{ _concat_addr( @{ $_[1] } ) }
        if $keys{$addr};
}

=head2 new_path($direct)

B<$direct> - направление потока

Возвращает ячейку для ключа

=cut

sub new_path {

    # Возвращает новый путь для хранения ключа хранилища
    return $keys{ _concat_addr( @{ $_[0] } ) }->{ _concat_addr( @{ $_[1] } ) } = {};
}

=head2 delete_path($direct)

B<$direct> - направление потока

Возвращает удаленный ключ для хранилища %store

=cut

sub delete_path {
    my $addr1 = _concat_addr( @{ $_[0] } );
    my $addr2 = _concat_addr( @{ $_[1] } );

    my $key = $keys{$addr1}->{$addr2}->{'key'};

    $keys{$addr1}->{$addr2} = undef;
    $keys{$addr1} = undef;
    delete $keys{$addr1};

    $keys{$addr2}->{$addr1} = undef;
    $keys{$addr2} = undef;
    delete $keys{$addr2};

    return $key;
}

# KEYS CONTROL ====

# ==== MAIN LOOP FILTERS
sub is_ipv4_packet { shift->{'eth'}->{'type'} == ETH_TYPE_IP }

sub is_tcp_proto { shift->{'ip'}->{'proto'} == IP_PROTO_TCP }

sub check_flag { ( $_[0] & $_[1] ) == $_[1] }

# MAIN LOOP FILTERS ====

# ==== OTHER SUPPORT FUNCTIONS
sub get_direction {
    my ($pack) = @_;

    my ( $ip1,   $ip2 )   = @{ $pack->{'ip'} }{qw/src dst/};
    my ( $port1, $port2 ) = @{ $pack->{'tcp'} }{qw/src_port dst_port/};

    my $addr1 = [ $ip1, $port1 ];
    my $addr2 = [ $ip2, $port2 ];

    return $addr1, $addr2 if wantarray;
    return [ $addr1, $addr2 ];
}

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

sub is_lan {
    return undef unless $_[0];
    return ( ( $_[0] & $NET_MASK ) == $NET_ADDR );
}

# OTHER SUPPORT FUNCTIONS ====

sub _verbose { say sprintf( shift, @_ ) if $VERBOSE }
sub _flow_name { $_[0]->{'ip_src'} . ' to ' . $_[0]->{'ip_dst'} }

__END__


=head1 NAME

Converter *.pcap file to netflow file

=head1 VERSION

Version 0.01

=head1 SYNOPSIS

  --file        Входной файл 
  --out         Выходной файл
  --filter      Файл с IP-адресами для исключения (по умолчанию: dns/digits.txt)
  --net         IP-адрес и маска локальной сети для исключения (по умолчанию: 192.168.0.0, 255.255.0.0)

  --verbose     Подробный вывод
  --help        Показать эту справку и выйти
=cut
