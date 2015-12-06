#!/usr/bin/perl

use warnings;
use strict;
use Net::Pcap;
use Net::Packet::Dump;
use Net::Packet::Consts qw(:dump);
use Socket;
use Data::Dumper;

$|=1;



use constant {
	NET_MASK => unpack('N', Socket::inet_aton("255.255.255.0")),
	LAN_NET  => unpack('N', Socket::inet_aton("192.168.2.0")),
};

my $cache = {};
my $it;

# Adress to Number
sub aton {
	# N - An unsigned long (32-bit) in "network" (big-endian) order
	return $cache->{'aton'}->{$_[0]} if defined $cache->{'aton'}->{$_[0]};
	return $cache->{'aton'}->{$_[0]} = unpack 'N', Socket::inet_aton($_[0]);
}

# Проверяет адрес принадлежности сети
sub compare {
	return undef unless $_[0]; 
	
	return ((&aton($_[0]) & NET_MASK) == LAN_NET);
}

# Открываем файл с преобразованными в числа IP адреса доменов (ТОП 50) 
open my $fh, '<', 'domains.digits.table';
my @table =  <$fh>;
close $fh;

# Ищет адрес в ТОП 100
sub find {
	return undef unless $_[0];
	
	# Ищет в ТОП 100 заданный адрес
	for $it (@table) { 
		($it == &aton($_[0])) && return 1; 
	}
}


my $dump = Net::Packet::Dump->new(
	mode => NP_DUMP_MODE_OFFLINE,
	file => 'netdump.pcap',
	unlinkOnClean => 0,
);

my $writer = Net::Packet::Dump->new(
	mode      => NP_DUMP_MODE_WRITER,
	file      => 'filtered.pcap',
	overwrite => 1,
	keepTimestamp => 1
);

$dump->start;
$writer->start;

my $sessions = {};
my $journal = {};
my ($key, $src, $dst);


# Осуществляет запись сессий в файл
sub save {
	my $key = shift;
	my $j = $journal->{$key};

	return undef unless defined $j;

	# Если сессия имее начало и конец, это то что нам нужно
	if ($j->{'BEGIN'} && $j->{'END'}) {
		for (@{$sessions->{$key}}) { 
			unless ($_) { next; } $writer->write($_); 
		} 
	}
	
	# Высвобождаем память 
	$sessions->{$key} = undef;
	$journal->{$key} = undef;

	delete $sessions->{$key};
	delete $journal->{$key};

	return 1;	
}


# Осуществляет ведение сессии
sub session {
	my $p = shift;
	($src, $dst) = ($p->l3->src || undef, $p->l3->dst || undef);
	
	return undef unless (defined $src && defined $dst);
	
	# Источник не из домашней сети, а получатель в домашней сети
	if ( !&compare($src) && &compare($dst) ) {
		# IP layer. IP address
		# Поменять адреса местами для формирования ключа
		($src, $dst) = ($p->l3->dst, $p->l3->src);	
	} else {
		($src, $dst) = ($p->l3->src, $p->l3->dst);
	}

	# Адрес получателя совпадает с ТОП 50 посещаемых сайтов
	return undef if (&find($dst));	
	
	$src =~ s/\.//g;
	$dst =~ s/\.//g;

	# IP.src_IP.dst
	$key = $src.'_'.$dst;
	
	$sessions->{$key} = [] unless (ref $sessions->{$key} eq 'ARRAY');	

	push @{$sessions->{$key}}, $p;

	# SYN or ACK, SYN
	if ($p->l4->flags == 0x002 || $p->l4->flags == 0x012 ) {
		if (defined $journal->{$key}->{'END'}) {
			&save($key);
			$sessions->{$key} = [];
		}

		# Регистрируем в журнале для этой сессии начало
		$journal->{$key}->{'BEGIN'} = 1;

		return 1; 
	}

	# ACK, FIN or FIN, PSH, ACK
	if ($p->l4->flags == 0x011 || $p->l4->flags == 0x019) {
		$journal->{$key}->{'END'} = 1;
#		&save($key);
	}

	return 1;
}

sub clearJournal {
	my @keys = keys %$journal;
	for $key (@keys) {
		&save($key);
	}
}

my ($packet);
my $i = 1;

print "Processed...\n";
while (1) {
	$packet = $dump->next;
	unless ($packet) {
		print "Clearng the journal... \n";
		&clearJournal();
		print "The journal has been cleared \n";
		last;
	}

	# Only IPv4	
	next unless $packet->l2->type == 0x0800;
	# Only TCP
	next unless $packet->l3->protocol == 0x06;

	# Если адрес источника и приемника это локальная сеть
	next if ( &compare($packet->l3->src) && &compare($packet->l3->dst) );

	# Если запрос не принадлежит ни к одной исследуемой сети
	next if ( !&compare($packet->l3->src) && !&compare($packet->l3->dst) );
	
	# Формируем сессию
	&session($packet);

}

print "Done... \n";

$writer->stop;
$dump->stop;

$writer->clean;
$dump->clean;

END {
	undef $sessions;
}

__END__

