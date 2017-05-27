#!/usr/bin/perl

use strict;
use warnings;
use feature ':5.10';

use IO::Handle;
use utf8;
use Getopt::Long 'HelpMessage';
use Time::Piece ':override';
use Socket qw(inet_aton);

use Net::Pcap;
use PP;
use NetPacket;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;

use Digest::MD5 qw/md5_hex/;
use Algorithm::Diff qw(sdiff);

use Data::Dumper;

GetOptions(
    'file=s'  => \my $pcap_in,
    'srcip=s' => \my $src_ip,    # IP адрес бота
    'dstip=s' => \my $dst_ip,    # IP адрес назначения
) or HelpMessage(1);

die "$0 requires the input filename argument (--srcip)\n" unless $src_ip;
die "$0 requires the input filename argument (--dstip)\n" unless $dst_ip;

die "$0 --srcip must have ip-address format"
    unless $src_ip =~ m/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
die "$0 --dstip must have ip-address format"
    unless $dst_ip =~ m/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;

my $SIMILARITY  = 0.75;
my $MIN_LCS_LEN = 6;

STDOUT->autoflush(1);

my $errbuf;
my $pcap = Net::Pcap::pcap_open_offline( $pcap_in, \$errbuf )
    or die("error reading pcap file: $errbuf");

my ( %header, $packet, %netpacket, $key, $direction, %storage );
while ( $packet = Net::Pcap::pcap_next( $pcap, \%header ) ) {
    next unless $packet;
    $netpacket{'eth'} = NetPacket::Ethernet->decode($packet);

    next unless $netpacket{'eth'}->{'data'};
    $netpacket{'ip'}  = NetPacket::IP->decode( $netpacket{'eth'}->{'data'} );

    # Only IPv4
    next unless $netpacket{'ip'}->{'ver'} == IP_VERSION_IPv4;

    # Only TCP
    next unless $netpacket{'ip'}->{'proto'} == IP_PROTO_TCP;

    $netpacket{'protocol'}
        = NetPacket::TCP->decode( $netpacket{'ip'}->{'data'} );

    if (   $src_ip eq $netpacket{'ip'}->{'src_ip'}
        && $dst_ip eq $netpacket{'ip'}->{'dest_ip'} )
    {

        $key = join '_', @{ $netpacket{'protocol'} }{qw\src_port dest_port\};
        $direction = 'request';
    }
    elsif ($src_ip eq $netpacket{'ip'}->{'dest_ip'}
        && $dst_ip eq $netpacket{'ip'}->{'src_ip'} )
    {
        $key = join '_', @{ $netpacket{'protocol'} }{qw\dest_port src_port\};
        $direction = 'response';
    }
    else {
        next;
    }

    my $flags       = $netpacket{'protocol'}->{'flags'};
    my $packet_data = $netpacket{'protocol'}->{'data'};

    if ( $flags && ( $flags & TCP_FLAG_SYN ) != 0 ) {
        if ( defined $storage{$key}->{'handshake'} ) {
            if ( $flags && ( $flags & TCP_FLAG_ACK ) != 0 ) {
                if ( defined $storage{$key}->{'established'} ) {
                    die "$0 caught SYN,ACK-flags after handshake";
                }
                else {
                    $storage{$key}->{'handshake'}++;
                }
            }
        }
        else {
            $storage{$key}->{'handshake'} = 1;
        }
        next;
    }

    if ( $flags && ( $flags & TCP_FLAG_ACK ) != 0 ) {
        if ( defined $storage{$key}->{'established'} ) {
            if ( length($packet_data) ) {
                $storage{$key}->{'queries'}->{$direction} = {
                    'data'   => $packet_data,
                    'source' => [ split '', unpack 'H*', $packet ]
                };

                $direction = undef;
            }
        }
        else {
            $storage{$key}->{'handshake'}++;
            $storage{$key}->{'established'}
                = $storage{$key}->{'handshake'} == 3;
            next;
        }

    }

    undef %netpacket;
}

my @storages_keys = sort keys %storage;
my $first_package = shift @storages_keys;

say $first_package;

# Отбираем только стабильные подключения и там где определен тип запроса request
my @established;
for (@storages_keys) {
    if ( $storage{$_}->{'established'}
        && defined $storage{$_}->{'queries'}->{'request'} )
    {
        # Изменять строку ниже
        push @established, $storage{$_}->{'queries'}->{'request'}->{'data'};
    }
}

# # ---- BELOW IS PROCESSING OF SIGNATURE -----

sub get_unique_signatures {
    my %signatures;

    $signatures{ md5_hex($_) } = $_ for @{ shift @_ };

    return [ values %signatures ];
}

sub sort_ascending {
    return [ sort { $a cmp $b } @{ shift @_ } ];
}

sub longest_common_subsequence {
    my @sings = @_;

    $_ = [ split '', $_ ] for @sings;

    my @sdiff = sdiff(@sings);

    my @letters;
    for ( my $i = 0; $i < @sdiff; ++$i ) {

        next unless lc $sdiff[$i][0] eq 'u';

        push @letters, $sdiff[$i][1];

    }

    return scalar @letters;
}

sub signature_similarity {

    # 0 - nothing in common
    # 1 - similar
    return ( 2 * $_[0] ) / ( length( $_[1] ) + length( $_[2] ) );
}

sub merge_signatures {
    my $sign_1 = [ split '', shift ];
    my $sign_2 = [ split '', shift ];

    # # Compare strings
    # # After that they are processed in a loop
    # # Result: @letters
    # # ---------------------------------------
    my @sdiff = sdiff( $sign_1, $sign_2 );

    my @letters;
    for my $item (@sdiff) {

        if ( lc $item->[0] eq 'u' ) {

            # # u: Element unmodified
            push @letters, $item->[1];
        }
        else {
            # # -,+,c: are processed here
            push @letters, "\x01";
        }

    }

    $sign_1 = join '', @letters;
    $sign_1 =~ s/\x01{2,}/\x01/g;
    return $sign_1;

}

my $list = \@established;
say 'Number of signatures: ' . scalar @$list;
say '--------------------------------------';
say Dumper \@established;
say '--------------------------------------';

# # Отбираем уникальные сигнатуры
$list = get_unique_signatures($list);
say 'Unique signatures: ' . scalar @$list;
say 'Necessary iterations: ' . scalar @$list - 1;
say '------------------';

# # Отсортируем сигнатуры
$list = &sort_ascending($list);

my @signatures_array;
my $transform_signature = shift @$list;
my $iteration           = 1;

for my $signature (@$list) {
    say "> iteration: " . $iteration;

    # # Определим самую большую подстроку
    my $lcs_length
        = longest_common_subsequence( $transform_signature, $signature );
    say 'lcs_length: ' . $lcs_length, ' | limit: ' . $MIN_LCS_LEN;

    # # Определим ранг схожести двух сигнатур
    my $similarity_rank
        = signature_similarity( $lcs_length, $transform_signature,
        $signature );
    say 'similarity_rank: ' . $similarity_rank, ' | limit: ' . $SIMILARITY;

# # 1. Чтобы не смешать сигнатуры двух ботов будем сравнивать их похожесть
# # 2. Убираем маленькие общие подстроки, чтобы уменьшить ложные срабатывания
    if ( $similarity_rank < $SIMILARITY || $lcs_length < $MIN_LCS_LEN ) {
        push @signatures_array, $transform_signature;
        $transform_signature = $signature;
        next;
    }

    # Объединяем сигнатуры
    $transform_signature
        = merge_signatures( $transform_signature, $signature );

    say '------------------';
    ++$iteration;
}

push @signatures_array, $transform_signature;

say Dumper \@signatures_array;
