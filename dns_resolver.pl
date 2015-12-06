#!/usr/bin/perl

use warnings;
use strict;
use Net::DNS;
use Data::Dumper;

$|=1;

my ($resolver, $reply);

$resolver = Net::DNS::Resolver->new(
	nameservers => ['8.8.8.8', '8.8.4.4', '78.29.2.21', '78.29.2.22']
);

sub resolv {
	my ($rslvr, $domain) = @_;
	my $reply = $rslvr->search($domain);
	#return $resolver->errorstring unless $reply;

	return undef unless $reply;

	my $addrs = [];
	foreach my $record ( $reply->answer ) {
		next unless $record->type eq "A";
		push @$addrs, $record->address;
	}
	return $addrs;
}

open (my $domains, '<', './domains.txt') 
	or die "cannot open file: $!";

open (my $n_domains, '> ./domains.table')
	or die "cannot open file: $!";

print "Processed...\n";
for (<$domains>) {
	chomp;

	next unless defined $_;

	# Отправляем запрос DNS серверам
	$reply = &resolv($resolver, $_);

	next unless $reply;

	# Сохраняем IP адрес
	# В таблицу IP адресов попадают домены с адресами, которые удалось получить
	print $n_domains '#'. $_ ."\n". (join ",", @$reply) ."\n"; 
}
print "Done...\n";

close ($n_domains);

close ($domains);
