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
    TEMP_FILE_EXT => '.dat',
    TEMP_FILE_TEMPLATE => 'PPFilterXXXXXXX',
    TEMP_FILE_DIR => 'tmp',
};

my ($cache, %sessions, %journal);

$cache = {
	aton => {},
	dns => {}
};

BEGIN {

	# Открываем файл с преобразованными в числа IP адреса доменов (ТОП 100) 
	open (TABLE, '<', 'domains.digits.table') or die $!;
	while (<TABLE>) { $cache->{'dns'}->{$_} = 1; }
	close TABLE;

}

sub tmp_fh {
	my $fh = shift;

	return close $fh if ref $fh eq "GLOB";

	return tempfile (
			DIR 		=> TEMP_FILE_DIR,
			TEMPLATE 	=> TEMP_FILE_TEMPLATE,
			SUFFIX 		=> TEMP_FILE_EXT,
			UNLINK 		=> 0,
		);
}

sub set_structure {
	return { 
				'FH' 	=> undef, 
				'FN' 	=> undef, 
				'BEGIN' => undef,
				'ND' 	=> undef, 
				'HDR' 	=> undef 
			};
}

sub main {
    my ($pcap, $packet, $errbuf, %header, $p, $pcap_dump);

    $pcap = pcap_open_offline(PCAP_IN, \$errbuf) or die ("error reading pcap file: $errbuf");
    
    $pcap_dump = Net::Pcap::dump_open($pcap, PCAP_OUT);
    unlink glob TEMP_FILE_DIR."/*".TEMP_FILE_EXT;

    my ($src, $dst, $key, $flags);
    while ( $packet = pcap_next($pcap, \%header) ) {
    	$src = $dst = $key = $flags = undef;

        $p = &PP::parse_packet($packet, \%header);

       	# Only IPv4 
        next unless $p->{'eth'}->{'type'} == ETH_TYPE_IP;

        # Only TCP
        next unless $p->{'ip'}->{'proto'} == IP_PROTO_TCP;

        ($src, $dst) = (&compare($p->{'ip'}->{'src'}), &compare($p->{'ip'}->{'dst'}));
        
        # Если адрес источника и приемника это локальная сеть
		next if ( $src && $dst );

		# Если запрос не принадлежит ни к одной исследуемой сети
		next if ( !$src && !$dst );

		# Источник не из домашней сети, а получатель в домашней сети
		if ( !$src && $dst ) {
			# Поменять адреса местами для будущего ключа
			($src, $dst) = @{$p->{'ip'}}{qw/dst src/};
		} else {
			($src, $dst) = @{$p->{'ip'}}{qw/src dst/};
		}

		next if $cache->{'dns'}->{ $dst } ? 1 : 0;

		# Socket::inet_ntoa(pack("N", $number))
		# IP.src_IP.dst
		$key = $src.'_'.$dst;

		unless ( exists $journal{$key} ) {
			$journal{$key} = &set_structure();
		}

		# Create a new temporary file
		unless (ref $journal{$key}->{'FH'} eq 'GLOB') {
			($journal{$key}->{'FH'}, $journal{$key}->{'FN'}) = &tmp_fh();
		}

		unless (ref $journal{$key}->{'HDR'} eq 'ARRAY') {
			$journal{$key}->{'HDR'} = [];
		}

		syswrite $journal{$key}->{'FH'}, "#START".$packet."FINISH#\n";
		push @{$journal{$key}->{'HDR'}}, \%header;

		$flags = $p->{'tcp'}->{'flags'};

		# SYN or ACK, SYN
		# Начало сессии
		if ( $flags == 0x002 || $flags == 0x012 ) {


			# Если по уже имеющимся данным у нас есть открытая сессия в журнале
        	if ( $journal{$key}->{'BEGIN'} && $journal{$key}->{'END'} ) {
        		my ($buf);

				open FH, "<", $journal{$key}->{'FN'};

				$buf = '';
				while ( <FH> ) {
					$buf .= $_;
					if ( m/^#START/ ) {
						$buf =~ s/#START//;
					}
					if ( m/FINISH#/ ) {
						$buf =~ s/FINISH#\n//;
						Net::Pcap::pcap_dump($pcap_dump, shift @{$journal{$key}->{'HDR'}}, $buf);
						Net::Pcap::pcap_dump_flush($pcap_dump);
						$buf = '';
					}
				}

				close FH;
				close $journal{$key}->{'FH'};
				undef $journal{$key};
				$journal{$key} = &set_structure();
        	}

	        # Регистрируем в журнале для этой сессии начало
	        $journal{$key}->{'BEGIN'} = 1;
		}

		# ACK, FIN or FIN, PSH, ACK
		# Завершение сессии
		if ( $flags == 0x011 || $flags == 0x019 ) {
			$journal{$key}->{'END'} = 1;
		}

		undef %header;
		undef $packet;
    } # .while

    print "Clear journal \n";
	my @keys = keys %journal;

	for $key ( @keys ) {
    	if ( $journal{$key}->{'BEGIN'} && $journal{$key}->{'END'} ) {
    		my ($buf);

			open FTMP, "<", $journal{$key}->{'FN'};

			$buf = '';
			while ( <FTMP> ) {
				$buf .= $_;
				if ( m/^#START/ ) {
					$buf =~ s/#START//;
				}
				if ( m/FINISH#/ ) {
					$buf =~ s/FINISH#\n//;
					Net::Pcap::pcap_dump($pcap_dump, shift @{$journal{$key}->{'HDR'}}, $buf);
					Net::Pcap::pcap_dump_flush($pcap_dump);
					$buf = '';
				}
			}

			close FTMP;
			close $journal{$key}->{'FH'};
			undef $journal{$key};
			delete $journal{$key};
    	}
	}
	Net::Pcap::dump_close($pcap_dump);
}

# Проверяет адрес принадлежности сети
sub compare {
	return undef unless $_[0]; 
	return (($_[0] & NET_MASK) == NET_ADDR);
}

# Ищет адрес в ТОП 100
sub find {
	return $cache->{'dns'}->{ $_[0] } ? 1 : 0;
}

&main();


__END__

