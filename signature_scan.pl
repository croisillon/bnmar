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

STDOUT->autoflush(1);

my $errbuf;
my $pcap = Net::Pcap::pcap_open_offline( $pcap_in, \$errbuf )
    or die("error reading pcap file: $errbuf");

my ( %header, $packet, %netpacket, $key, $direction, %storage );
while ( $packet = Net::Pcap::pcap_next( $pcap, \%header ) ) {
    $netpacket{'eth'} = NetPacket::Ethernet->decode($packet);
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

    if ( ( $flags & TCP_FLAG_SYN ) != 0 ) {
        if ( defined $storage{$key}->{'handshake'} ) {
            if ( ( $flags & TCP_FLAG_ACK ) != 0 ) {
            	if ( defined $storage{$key}->{'established'} ) {
            		die "$0 caught SYN,ACK-flags after handshake";
        		} else {
            		$storage{$key}->{'handshake'}++;
        		}
            }
        }
        else {
            $storage{$key}->{'handshake'} = 1;
        }
        next;
    }

    if ( ( $flags & TCP_FLAG_ACK ) != 0 ) {
        if ( defined $storage{$key}->{'established'} ) {
            if ( length($packet_data) ) {
                push @{ $storage{$key}->{'queries'} },
                    { $direction => $packet_data };
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

# Наибольшая длина последовательности
# use LCS;
# my $lcs = LCS->LCS( [split '', "thisisatest"], [split '', "testing123testing"] );
# say lcs("thisisatest", "testing123testing");


# Наибольшая длина подстроки
# use String::LCSS_XS qw(lcss lcss_all);
# my $longest = lcss( "thisisatest", "testing123testing" );
# print $longest, "\n";



# say Dumper \%storage;