#!/usr/bin/perl

use warnings;
use strict;
use Net::DNS;

$|=1;

my ($resolver, $reply);

use constant IN => 'domains.txt';
use constant OUT => 'domains.table';

=encoding utf8

=head1 NAME

DNS Resolver

=head1 SYNOPSIS

Преобразует доменные имена в ip-адреса

=head1 DESCRIPTION

Обращается к DNS-серверам для получения ip-адресов для доменных имен.
Для каждого доменного имени получает все возможные ip-адреса.
Результат записывается в файл с сохранением доменного имени и принадлежащих ему ip-адресов.

=head2 Functions

=over 1

=item C<resolv(resolv, domain)>
    Возвращает ссылку на массив после обработки запросов к DNS-серверам
    В результатах фильтрует только записи типа "A"

=back

=head1 AUTHOR

Denis Lavrov C<diolavr@gmail.com>

=cut

$resolver = Net::DNS::Resolver->new(
	nameservers => ['8.8.8.8', '8.8.4.4']
);

sub resolv {
	my ($rslvr, $domain) = @_;
	my $reply = $rslvr->search($domain);

	return undef unless $reply;

	my $addrs = [];
	foreach my $record ( $reply->answer ) {
		next unless $record->type eq "A";
		push @$addrs, $record->address;
	}
	return $addrs;
}



open (my $domains, '<', IN) 
	or die "cannot open file: $!";

open (my $n_domains, '>', OUT)
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

__END__
