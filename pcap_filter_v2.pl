#!/usr/bin/perl

use warnings;
use strict;
use Net::Pcap;
use Data::Dumper;

$|=1;

use constant {
	NET_MASK => unpack('N', Socket::inet_aton("255.255.255.0")),
	LAN_NET  => unpack('N', Socket::inet_aton("192.168.2.0")),
	PCAP_FILE => "123.pcap",
};

use constant {
	BIT_HEADER_ETH 				=> 112, # 112 bits [rfc826]
	BIT_ETHERNET_DESTINATION 	=> 48, 	# Destination mac address
	BIT_ETHERNET_SOURCE 		=> 48, 	# Source mac address
	BIT_ETHERNET_TYPE 			=> 16, 	# Type

	BIT_HEADER_IP  				=> 160, # 160 bits [rfc791]
	BIT_IP_VERSION				=> 4, 	# Version
	BIT_IP_IHL 					=> 4, 	# Internet Header Length
	BIT_IP_TOS 					=> 8, 	# Type of service
	BIT_IP_TOL 					=> 16, 	# Total length
	BIT_IP_ID 					=> 16, 	# Identification
	BIT_IP_FLAGS 				=> 3, 	# Flags
	BIT_IP_FRAGMENTS 			=> 13, 	# Fragment offset
	BIT_IP_TTL 					=> 8, 	# Time to live
	BIT_IP_PROTOCOL 			=> 8, 	# Protocol
	BIT_IP_CHECKSUM 			=> 16, 	# Header Checksum
	BIT_IP_SRCADDRESS 			=> 32, 	# Source address
	BIT_IP_DSTADDRESS 			=> 32, 	# Destination address

	BIT_HEADER_TCP 				=> 160, # 160 bits [rfc793]
	BIT_TCP_SRCPORT				=> 16,	# Source Port
	BIT_TCP_DSTPORT				=> 16, 	# Destination Port
	BIT_TCP_SEQNUM				=> 32, 	# Sequence Number
	BIT_TCP_ACKNUM				=> 32, 	# Acknowledgment Number
	BIT_TCP_OFFSET				=> 4, 	# Data Offset
	BIT_TCP_RESERVED			=> 6, 	# Reserved
	BIT_TCP_CTRLBITS			=> 6, 	# Control Bits (from left to right)
	BIT_TCP_WINDOW				=> 16, 	# Window
	BIT_TCP_CHECKSUM			=> 16, 	# Checksum
	BIT_TCP_UPOINTER			=> 16, 	# Urgent Pointer
};

sub main {
	my ($pcap, $packet, $errbuf, %header);
	my ($eth, $ip, $tcp, $tmpl);

	$tmpl = 'B'.BIT_HEADER_ETH;
	$tmpl .= 'B'.BIT_HEADER_IP;
	$tmpl .= 'B'.BIT_HEADER_TCP;

	$pcap = pcap_open_offline(PCAP_FILE, \$errbuf) or die ("error reading pcap file: $errbuf");

	$packet = pcap_next($pcap, \%header);

	($eth, $ip, $tcp) = unpack $tmpl, $packet;

	$eth = parse_ethernet_layer($eth);

	$ip = parse_ip_layer($ip);

	$tcp = parse_tcp_layer($tcp);

	print Dumper $tcp;

	pcap_close($pcap);

}

sub parse_ethernet_layer {
	my $packet = shift;
	my ($tmpl, %eth);

	$tmpl = 'A'.BIT_ETHERNET_DESTINATION;
	$tmpl .= 'A'.BIT_ETHERNET_SOURCE;
	$tmpl .= 'A'.BIT_ETHERNET_TYPE;

	($eth{'dst'}, $eth{'src'}, $eth{'type'}) = map { eval "0b$_" } unpack $tmpl, $packet;

	return \%eth;
}

sub parse_ip_layer {
	my $packet = shift;
	my ($tmpl, %ip);

	$tmpl = 'A'.BIT_IP_VERSION;
	$tmpl .= 'A'.BIT_IP_IHL;
	$tmpl .= 'A'.BIT_IP_TOS;
	$tmpl .= 'A'.BIT_IP_TOL;
	$tmpl .= 'A'.BIT_IP_ID;
	$tmpl .= 'A'.BIT_IP_FLAGS;
	$tmpl .= 'A'.BIT_IP_FRAGMENTS;
	$tmpl .= 'A'.BIT_IP_TTL;
	$tmpl .= 'A'.BIT_IP_PROTOCOL;
	$tmpl .= 'A'.BIT_IP_CHECKSUM;
	$tmpl .= 'A'.BIT_IP_SRCADDRESS;
	$tmpl .= 'A'.BIT_IP_DSTADDRESS;

	(
		$ip{'ver'}, $ip{'hlen'}, $ip{'tos'}, $ip{'len'}, 
		$ip{'id'}, $ip{'flags'}, $ip{'frag_offset'}, $ip{'ttl'}, 
		$ip{'proto'}, $ip{'checksum'}, $ip{'src'}, $ip{'dst'}
	) = map { eval "0b$_" } unpack $tmpl, $packet;

	return \%ip;
}

sub parse_tcp_layer {
	my $packet = shift;
	my ($tmpl, %tcp);

	$tmpl = 'A'.BIT_TCP_SRCPORT;
	$tmpl .= 'A'.BIT_TCP_DSTPORT;
	$tmpl .= 'A'.BIT_TCP_SEQNUM;
	$tmpl .= 'A'.BIT_TCP_ACKNUM;
	$tmpl .= 'A'.BIT_TCP_OFFSET;
	$tmpl .= 'A'.BIT_TCP_RESERVED;
	$tmpl .= 'A'.BIT_TCP_CTRLBITS;
	$tmpl .= 'A'.BIT_TCP_WINDOW;
	$tmpl .= 'A'.BIT_TCP_CHECKSUM;
	$tmpl .= 'A'.BIT_TCP_UPOINTER;

	(
		$tcp{'src_port'}, $tcp{'dst_port'}, $tcp{'seq_num'}, $tcp{'ack_num'},
		$tcp{'offset'}, $tcp{'reserved'}, $tcp{'flags'}, $tcp{'window'},
		$tcp{'checksum'}, $tcp{'upointer'} 
	) = map { eval "0b$_" } unpack $tmpl, $packet;

	return \%tcp;
}


&main();

__END__

