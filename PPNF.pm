package PPNF;

# 0 - Date first seen   +
# 1 - Time              +
# 2 - Duration          +
# 3 - Proto             +
# 4 - SRC IP Addr:Port  +
# 5 - Arrow             /
# 6 - DST IP Addr:Port  +
# 7 - Flags
# 8 - Tos               +
# 9 - Packets           +
# 10 - Bytes            +
# 11 - pps              +
# 12 - bps              +
# 13 - Bpp              +
# 14 - Flows            +

use strict;
use Time::Piece ':override';
use Socket;

require v5.18;

our $VERSION = '0.01';

require Exporter;
our @ISA = qw(Exporter);

use constant {
    BIT_HEADER_ETH           => 112,    # 112 bits [rfc826]
    BIT_ETHERNET_DESTINATION => 48,     # Destination mac address
    BIT_ETHERNET_SOURCE      => 48,     # Source mac address
    BIT_ETHERNET_TYPE        => 16,     # Type

    BIT_HEADER_IP     => 160,           # 160 bits [rfc791]
    BIT_IP_VERSION    => 4,             # Version
    BIT_IP_IHL        => 4,             # Internet Header Length
    BIT_IP_TOS        => 8,             # Type of service
    BIT_IP_TOL        => 16,            # Total length
    BIT_IP_ID         => 16,            # Identification
    BIT_IP_FLAGS      => 3,             # Flags
    BIT_IP_FRAGMENTS  => 13,            # Fragment offset
    BIT_IP_TTL        => 8,             # Time to live
    BIT_IP_PROTOCOL   => 8,             # Protocol
    BIT_IP_CHECKSUM   => 16,            # Header Checksum
    BIT_IP_SRCADDRESS => 32,            # Source address
    BIT_IP_DSTADDRESS => 32,            # Destination address

    BIT_HEADER_TCP   => 160,            # 160 bits [rfc793]
    BIT_TCP_SRCPORT  => 16,             # Source Port
    BIT_TCP_DSTPORT  => 16,             # Destination Port
    BIT_TCP_SEQNUM   => 32,             # Sequence Number
    BIT_TCP_ACKNUM   => 32,             # Acknowledgment Number
    BIT_TCP_OFFSET   => 4,              # Data Offset
    BIT_TCP_RESERVED => 6,              # Reserved
    BIT_TCP_CTRLBITS => 6,              # Control Bits (from left to right)
    BIT_TCP_WINDOW   => 16,             # Window
    BIT_TCP_CHECKSUM => 16,             # Checksum
    BIT_TCP_UPOINTER => 16,             # Urgent Pointer
};

use constant {
    ETH_TYPE_IP => 0x0800,

    IP_PROTO_TCP => 6,
    IP_PROTO_UDP => 17,

    IP_VERSION_IPv4 => 4,

    TCP_FLAG_FIN => 0x01,
    TCP_FLAG_SYN => 0x02,
    TCP_FLAG_RST => 0x04,
    TCP_FLAG_PSH => 0x08,
    TCP_FLAG_ACK => 0x10,
    TCP_FLAG_URG => 0x20,
    TCP_FLAG_ECE => 0x40,
    TCP_FLAG_CWR => 0x80,
};

our @EXPORT = qw(
    ETH_TYPE_IP IP_PROTO_TCP IP_PROTO_UDP IP_VERSION_IPv4
    TCP_FLAG_FIN TCP_FLAG_SYN TCP_FLAG_RST TCP_FLAG_PSH TCP_FLAG_ACK
    TCP_FLAG_URG TCP_FLAG_ECE TCP_FLAG_CWR
);

our @EXPORT_OK = qw(parse_string toDotQuad);

our %EXPORT_TAGS = (
    ALL    => [ @EXPORT, @EXPORT_OK ],
    pparse => [qw(parse_string toDotQuad)],
);

sub toDotQuad {
    my ($i) = @_;
    ( $i >> 24 & 255 ) . '.'
        . ( $i >> 16 & 255 ) . '.'
        . ( $i >> 8 & 255 ) . '.'
        . ( $i & 255 );
}

sub parse_string {
    my $packet = shift;
    my $header = shift;
    my ( $ip, $eth, $tcp, $tmpl );

    $tmpl = [split /\s+/, $packet];

    ($header->{'tv_sec'}, $header->{'tv_usec'}) = (split /\./, $tmpl->[1]);
    $header->{'tv_sec'} = Time::Piece->strptime($tmpl->[0].' '.$header->{'tv_sec'},"%Y-%m-%d %H:%M:%S");

    # $tmpl = 'B' . BIT_HEADER_ETH;
    # $tmpl .= 'B' . BIT_HEADER_IP;
    # $tmpl .= 'B' . BIT_HEADER_TCP;

    # ( $eth, $ip, $tcp ) = unpack $tmpl, $packet;

    $eth = &parse_ethernet_layer($tmpl);
    $ip  = &parse_ip_layer($tmpl);
    $tcp = &parse_tcp_layer($tmpl);

    return {
        'eth'    => {},
        'ip'     => $ip,
        'tcp'    => $tcp,
        'hdr'    => $header,
        'source' => $packet,
        'nf' => {
            'pps' => $tmpl->[11],
            'bps' => $tmpl->[12],
            'bpp' => $tmpl->[13],
            'flows' => $tmpl->[14],
            'duration' => $tmpl->[2],
            'ppf' => $tmpl->[9]
        }
    };

}

sub parse_ethernet_layer {
    my $packet = shift;
    my ( $tmpl, %eth );

    # $tmpl = 'A' . BIT_ETHERNET_DESTINATION;
    # $tmpl .= 'A' . BIT_ETHERNET_SOURCE;
    # $tmpl .= 'A' . BIT_ETHERNET_TYPE;

    ( $eth{'dst'}, $eth{'src'}, $eth{'type'} )
        = (undef, undef, undef);

    return \%eth;
}

sub parse_ip_layer {
    my $packet = shift;
    my ( $tmpl, %ip );

    # $tmpl = 'A' . BIT_IP_VERSION;
    # $tmpl .= 'A' . BIT_IP_IHL;
    # $tmpl .= 'A' . BIT_IP_TOS;
    # $tmpl .= 'A' . BIT_IP_TOL;
    # $tmpl .= 'A' . BIT_IP_ID;
    # $tmpl .= 'A' . BIT_IP_FLAGS;
    # $tmpl .= 'A' . BIT_IP_FRAGMENTS;
    # $tmpl .= 'A' . BIT_IP_TTL;
    # $tmpl .= 'A' . BIT_IP_PROTOCOL;
    # $tmpl .= 'A' . BIT_IP_CHECKSUM;
    # $tmpl .= 'A' . BIT_IP_SRCADDRESS;
    # $tmpl .= 'A' . BIT_IP_DSTADDRESS;

    my %protos = (
        'TCP' => IP_PROTO_TCP,
        'UDP' => IP_PROTO_UDP
    );

    %ip = (
        'ver' => IP_VERSION_IPv4,
        'hlen' => 0,
        'tos' => $packet->[8],
        'len' => $0,
        'id' => 0,
        'flags' => 0,
        'frag_offset' => 0,
        'ttl' => 0,
        'proto' => $protos{uc $packet->[3]} || 0,
        'checksum' => 0,
        'src' => unpack("N", inet_aton([split ':', $packet->[4]]->[0])),
        'dst' => unpack("N", inet_aton([split ':', $packet->[6]]->[0])),
    );

    # (   $ip{'ver'},         $ip{'hlen'}, $ip{'tos'},
    #     $ip{'len'},         $ip{'id'},   $ip{'flags'},
    #     $ip{'frag_offset'}, $ip{'ttl'},  $ip{'proto'},
    #     $ip{'checksum'},    $ip{'src'},  $ip{'dst'}
    # )

    return \%ip;
}

sub parse_tcp_layer {
    my $packet = shift;
    my ( $tmpl, %tcp );

    $tmpl = 'A' . BIT_TCP_SRCPORT;
    $tmpl .= 'A' . BIT_TCP_DSTPORT;
    $tmpl .= 'A' . BIT_TCP_SEQNUM;
    $tmpl .= 'A' . BIT_TCP_ACKNUM;
    $tmpl .= 'A' . BIT_TCP_OFFSET;
    $tmpl .= 'A' . BIT_TCP_RESERVED;
    $tmpl .= 'A' . BIT_TCP_CTRLBITS;
    $tmpl .= 'A' . BIT_TCP_WINDOW;
    $tmpl .= 'A' . BIT_TCP_CHECKSUM;
    $tmpl .= 'A' . BIT_TCP_UPOINTER;

    %tcp = (
        'src_port' => [split ':', $packet->[4]]->[1],
        'dst_port' => [split ':', $packet->[6]]->[1],
        'seq_num' => 0,
        'ack_num' => 0,
        'offset' => 0,
        'reserved' => 0,
        'flags' => 0,
        'window' => 0,
        'checksum' => 0,
        'upointer' => 0
    );

    # (   $tcp{'src_port'}, $tcp{'dst_port'}, $tcp{'seq_num'},
    #     $tcp{'ack_num'},  $tcp{'offset'},   $tcp{'reserved'},
    #     $tcp{'flags'},    $tcp{'window'},   $tcp{'checksum'},
    #     $tcp{'upointer'}
    # )

    return \%tcp;
}

1;
