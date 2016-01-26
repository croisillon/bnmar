#!/usr/bin/perl

use common::sense;
use Net::DNS;

select STDOUT;
$| = 1;

my $args = {@ARGV};

my ( $resolver, $reply );

if ( exists $args->{'--help'} || exists $args->{'-h'} ) {
    &_help();
    exit 1;
}

my $IN = $args->{'-i'} || $args->{'--input'} || 'domains.txt';

die qq{File "$IN" is not found\n}   unless -e $IN;
die qq{FIle "$IN" cannot be read\n} unless -r $IN;

my $OUT = $args->{'-o'} || $args->{'--output'} || 'domains.table';

my $NS = $args->{'-s'} || $args->{'--dns'} || '8.8.8.8, 8.8.4.4';

$NS =~ s/\s//g;
$NS = [split ',', $NS];

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

$resolver = Net::DNS::Resolver->new( nameservers => $NS );

open( my $in_fh, '<', $IN )
    or die "cannot open file: $!\n";

open( my $out_fh, '>', $OUT )
    or die "cannot open file: $!\n";

print "Processed...\n";
for (<$in_fh>) {
    chomp;

    next unless defined $_;

    # Отправляем запрос DNS серверам
    $reply = &resolv( $resolver, $_ );

    next unless $reply;

# Сохраняем IP адрес
# В таблицу IP адресов попадают домены с адресами, которые удалось получить
    print $out_fh '#' . $_ . "\n";
    print $out_fh ( join ',', @$reply ) . "\n";
}
print "Done...\n";

close($out_fh);
close($in_fh);

sub resolv {
    my ( $rslvr, $domain ) = @_;
    my $reply = $rslvr->search($domain);

    return undef unless $reply;

    my $addrs = [];
    foreach my $record ( $reply->answer ) {
        next unless $record->type eq "A";
        push @$addrs, $record->address;
    }
    return $addrs;
}

sub _help {
    print qq{Использование: dns_resolver.pl [-i FILE] [-o FILE] [-s DNS [,DNS]] \n},
    q{Считывает список доменов из файла. },
    q{Для каждого домена получает IP-адреса. },
    qq{Результат записывается в файл с сохранением домена.\n\n};

    print sprintf("%5s, %s\t %s", '-i', '--input',  q{Входной файл (по умолчанию: domains.txt)}), "\n";
    print sprintf("%5s, %s\t %s", '-o', '--output', q{Выходной файл (по умолчанию: domains.table)}), "\n";
    print sprintf("%5s, %s\t %s", '-s', '--dns', q{Список DNS-серверов через запятую (по умолчанию: 8.8.8.8, 8.8.4.4)}), "\n";
    print "\n";
    print sprintf("%6s %s\t %s", '', '--help', q{Показать эту справку и выйти}), "\n";
    print "\n";

    print qq{Примеры: \n},
    q{dns_resolver.pl -o ip_adreses.txt -s 77.77.8.8, 8.8.8.8}, "\n",
    q{dns_resolver.pl -s 8.8.8.8}, "\n\n";
}

__END__
