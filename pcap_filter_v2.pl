#!/usr/bin/perl

use warnings;
use strict;
use Net::Pcap;
use Socket qw(inet_aton);
use Data::Dumper;
use File::Temp qw/ tempfile tempdir /;
use PP;

select STDOUT;
$|=1;

use constant {
	NET_MASK => unpack('N', Socket::inet_aton("255.255.255.0")),
	NET_ADDR  => unpack('N', Socket::inet_aton("192.168.2.0")),
	PCAP_IN  => "netdump.pcap",
	PCAP_OUT => 'filtered.pcap',
	TEMP_FILE_EXT => '.pcap',
	TEMP_FILE_DIR => '/tmp',
};

use constant VERBOSE => 0;

my (%cache, %sessions, %journal);

BEGIN {

	# Открываем файл с преобразованными в числа IP адреса доменов (ТОП 100) 
	open (TABLE, '<', 'domains.digits.table') or die $!;
	while (<TABLE>) { $cache{$_} = 1; }
	close TABLE;

}

sub main {
	my ($pcap, $packet, $errbuf, %header, $p, $pcap_dump);
<<<<<<< HEAD
	my ($src, $dst, $key, $flags);
=======
	my ($src_ip, $dst_ip, $key, $flags, $src_port, $dst_port);
>>>>>>> 67f39e8... Temporary files are replaced with files pcap

	$pcap = pcap_open_offline(PCAP_IN, \$errbuf) or die ("error reading pcap file: $errbuf");
	
	$pcap_dump = Net::Pcap::dump_open($pcap, PCAP_OUT);

	print "Start parsing file ".PCAP_IN."\n";
	while ( $packet = pcap_next($pcap, \%header) ) {

		$p = &PP::parse_packet($packet, \%header);

		# Only IPv4 
		next unless $p->{'eth'}->{'type'} == ETH_TYPE_IP;

		# Only TCP
		next unless $p->{'ip'}->{'proto'} == IP_PROTO_TCP;

<<<<<<< HEAD
		$src = &compare($p->{'ip'}->{'src'});
		$dst = &compare($p->{'ip'}->{'dst'});
		
		# If the source and destination address is a local area network
		next if ( $src && $dst );

		# If the request does not belong to any study network
		next if ( !$src && !$dst );

		# The source is not from the home network and the receiver in the home network
		if ( !$src && $dst ) {
=======
		$src_ip = &compare($p->{'ip'}->{'src'});
		$dst_ip = &compare($p->{'ip'}->{'dst'});
		
		# If the source and destination address is a local area network
		next if ( $src_ip && $dst_ip );

		# If the request does not belong to any study network
		next if ( !$src_ip && !$dst_ip );

		# The source is not from the home network and the receiver in the home network
		if ( !$src_ip && $dst_ip ) {
>>>>>>> 67f39e8... Temporary files are replaced with files pcap
			# Поменять адреса местами для будущего ключа
			($src_ip, $dst_ip) = @{$p->{'ip'}}{qw/dst src/};
			($src_port, $dst_port) = @{$p->{'tcp'}}{qw/dst_port src_port/};
		} else {
			($src_ip, $dst_ip) = @{$p->{'ip'}}{qw/src dst/};
			($src_port, $dst_port) = @{$p->{'tcp'}}{qw/src_port dst_port/};
		}

		# Search address in the list of top 100
<<<<<<< HEAD
		next if defined $cache{ $dst };
=======
		next if defined $cache{ $dst_ip };
>>>>>>> 67f39e8... Temporary files are replaced with files pcap

		# IP.src_IP.dst
		$key = $src_ip.$dst_ip.$src_port.$dst_port;

		# Create a new temporary file [ip.src_ip.dst.pcap]
		unless (ref $journal{$key}->{'FH'} eq ref $pcap_dump) {

			# Filename
			$journal{$key}->{'FN'} = TEMP_FILE_DIR.'/'.$key.TEMP_FILE_EXT;

			# Filehandle
			$journal{$key}->{'FH'} = Net::Pcap::dump_open($pcap,$journal{$key}->{'FN'});
		}

		# Recording package to a temporary file
		Net::Pcap::pcap_dump($journal{$key}->{'FH'}, \%header, $packet);
		Net::Pcap::pcap_dump_flush($journal{$key}->{'FH'});

		$flags = $p->{'tcp'}->{'flags'};

		# SYN or ACK, SYN
		# Начало сессии
		if ( $flags == TCP_FLAG_SYN || $flags == (TCP_FLAG_ACK + TCP_FLAG_SYN) ) {

			# Если по уже имеющимся данным у нас есть открытая сессия в журнале
			if ( $journal{$key}->{'BEGIN'} && $journal{$key}->{'END'} ) {

				print "Moving the session $key in the main file \n" if VERBOSE;
				Net::Pcap::dump_close($journal{$key}->{'FH'});

<<<<<<< HEAD
				&save($journal{$key}->{'FN'}, $pcap_dump);
=======
				&move_to($journal{$key}->{'FN'}, $pcap_dump);
>>>>>>> 67f39e8... Temporary files are replaced with files pcap

				undef $journal{$key};
			}

			# Регистрируем в журнале для этой сессии начало
			$journal{$key}->{'BEGIN'} = 1;
		} # .if

		# ACK, FIN or FIN, PSH, ACK
		# Завершение сессии
		if ( $flags == (TCP_FLAG_FIN + TCP_FLAG_ACK) || $flags == (TCP_FLAG_PSH + TCP_FLAG_FIN + TCP_FLAG_ACK) ) {
			$journal{$key}->{'END'} = 1;
		}

		undef %header;
<<<<<<< HEAD
		$src = $dst = $key = $flags = $packet = undef;
=======
		$src_ip = $dst_ip = $key = $flags = $packet = undef;
>>>>>>> 67f39e8... Temporary files are replaced with files pcap
	} # .while
	print "Parsing has been completed\n";

	print "Clear journal \n";
	my @keys = keys %journal;

	for $key ( @keys ) {
			if ( $journal{$key}->{'BEGIN'} && $journal{$key}->{'END'} ) {

				print "Moving the session $key in the main file \n" if VERBOSE;
				Net::Pcap::dump_close($journal{$key}->{'FH'});

<<<<<<< HEAD
				&save($journal{$key}->{'FN'}, $pcap_dump);
=======
				&move_to($journal{$key}->{'FN'}, $pcap_dump);
>>>>>>> 67f39e8... Temporary files are replaced with files pcap

				undef $journal{$key};
			}
	}

	Net::Pcap::dump_close($pcap_dump);
	Net::Pcap::pcap_close($pcap);

	# Garbage collection
	print "Garbage collection\n";
	unlink glob TEMP_FILE_DIR."/*".TEMP_FILE_EXT;

	sleep(2);
}

# Проверяет адрес принадлежности сети
sub compare {
	return undef unless $_[0]; 
	return (($_[0] & NET_MASK) == NET_ADDR);
}

<<<<<<< HEAD
sub save {
=======
sub move_to {
>>>>>>> 67f39e8... Temporary files are replaced with files pcap
	my $fn = shift;   # $journal{$key}->{'FN'}
	my $dump = shift; # $pcap_dump

	my $i = 0;

	my ($pcap, $errbuf, $packet, %header);

	$pcap = pcap_open_offline($fn, \$errbuf);

	while ( $packet = pcap_next($pcap, \%header) ) {
		++$i;
		Net::Pcap::pcap_dump($dump, \%header, $packet);
		Net::Pcap::pcap_dump_flush($dump);
	}
	print "Recorded in the main file packages -> $i \n" if VERBOSE;

	Net::Pcap::pcap_close($pcap);

	return 0;
}

&main();


__END__

