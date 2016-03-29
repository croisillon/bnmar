#!/usr/bin/perl

use common::sense;
use Getopt::Long 'HelpMessage';
use Net::DNS;

select STDOUT;
$| = 1;

my ( $file, $out, @dns, $lookup );

GetOptions(
    'file=s'   => \$file,
    'out=s'    => \$out,
    'dns=s{,}' => \@dns,
    'lookup'   => \$lookup,
    'help'     => sub { HelpMessage(0) }
) or HelpMessage(1);

# Defaults
$file = $file || 'domains.txt';
$out = $out || 'domains.table.txt';
@dns = scalar @dns ? @dns : ('8.8.8.8', '8.8.4.4');

map { chomp $_; } @dns;

if ( 1 == scalar @dns ) {
    $dns[0] =~ s/\s//g;
    @dns = split ',', $dns[0];
}

die qq{File "$file" is not found\n} unless -e $file;
die qq{FIle "$file" cannot be read\n} unless -r $file;

my ( $resolver, $reply, $in_fh, $out_fh );
$resolver = Net::DNS::Resolver->new( nameservers => \@dns );

open( $in_fh, '<', $file )
    or die "Cannot open file: $!\n";

open( $out_fh, '>', $out )
    or die "Cannot open file: $!\n";

say "Processed...";
for (<$in_fh>) {
    chomp;

    next unless defined $_;

    # Отправляем запрос DNS серверам
    $reply = &find( $resolver, $_ );

    # Проверяем состояние
    unless ($reply) {
        unless ( $lookup ) {
            say qq{Hostname $_ cannot be resolved to IP address};
        } else {
            say qq{IP address $_ font found};
        }
        next;
    }

    print $out_fh '#' . $_ . "\n";
    print $out_fh ( join ',', @$reply ) . "\n";
}
say "Done";

close($out_fh);
close($in_fh);

sub find {
    my ( $rsl, $rec ) = @_;

    my $reply = $rsl->search($rec);

    return undef unless $reply;

    my @ip;
    foreach my $rec ( $reply->answer ) {
        if ( $lookup ) {
            next unless $rec->type eq "PTR";
            push @ip, $rec->ptrdname;
        } else {
            next unless $rec->type eq "A";
            push @ip, $rec->address;
        }
    }

    return \@ip;
}

__END__

=head1 NAME

DNS Resolver

=head1 VERSION

Version 0.04

=head1 SYNOPSIS

 dns_resolver.pl [КЛЮЧ]

 -f, --file        Входной файл (по умолчанию: domains.txt)
 -o, --out         Выходной файл (по умолчанию: domains.table)
 -d, --dns         Список DNS-серверов через запятую (по умолчанию: 8.8.8.8, 8.8.4.4)
     --lookup      Произвести поиск домена по IP-адресу

     --help        Показать эту справку и выйти

=head2 Примеры

 dns_resolver.pl --out ip_adreses.txt --dns 77.77.8.8, 8.8.8.8
 dns_resolver.pl -d 8.8.8.8
 dns_resolver.pl --lookup

=head2 Формат входного файла

=over

=item topf1le.com

=item adobe.com

=item  mmrdrtrckms.com

=item  163.com

=item leboncoin.fr

=item espn.go.com

=item  jd.com

=item  news.yahoo.com

=item  answers.yahoo.com

=item  wikia.com 

=item ...

=back

=head2 Формат выходного файла

=over

=item #adobe.com

=item 192.150.16.117

=item #163.com

=item 123.58.180.7,123.58.180.8

=item ...

=back

=head1 DESCRIPTION

Обращается к DNS-серверам для получения ip-адресов доменных имен.
Для каждого доменного имени получает все возможные ip-адреса.
Результат записывается в файл с сохранением доменного имени и принадлежащих ему ip-адресов.
Если используется ключ --lookup то произойдет поиск доменного имени по IP-адресу

=head2 Functions

=over 1

=item C<find(resolv, rec)>
    Возвращает ссылку на массив после обработки запросов к DNS-серверам
    В результатах фильтрует только записи типа "A"
    В случае когда надо найти домены вернет ссылки типа PTR

=back

=head1 AUTHOR

Denis Lavrov (C<diolavr@gmail.com>)

=cut
