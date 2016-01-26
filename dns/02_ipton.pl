#!/usr/bin/perl

use common::sense;
use Socket qw/inet_aton/;

select STDOUT;
$| = 1;

my $args = {@ARGV};

my ( $resolver, $reply );

if ( exists $args->{'--help'} || exists $args->{'-h'} ) {
    &_help();
    exit 1;
}

my $IN = $args->{'-i'} || $args->{'--input'} || 'domains.table.txt';

die qq{File "$IN" is not found\n}   unless -e $IN;
die qq{FIle "$IN" cannot be read\n} unless -r $IN;

my $OUT = $args->{'-o'} || $args->{'--output'} || 'domains.digits.txt';

=encoding utf8

=head1 NAME

IP address to Number

=head1 SYNOPSIS

Преобразует ip-адреса в числа

=head1 AUTHOR

Denis Lavrov C<diolavr@gmail.com>

=cut

open my $in_fh, '<', $IN  or die $! . "\n";
open my $out_fh,  '>', $OUT or die $! . "\n";

print "Processed...\n";
for (<$in_fh>) {
    if ( $_ =~ m/^#/ ) { next; }
    map { print $out_fh ( unpack 'N', &inet_aton($_) ), "\n"; }
        split ',', $_;
}
print "Done...\n";

close($in_fh);
close($out_fh);

sub _help {
    print qq{Использование: ipton.pl [-i FILE] [-o FILE]] \n},
    q{Преобразует IP-адреса в числа },
    qq{Результат записывается в файл.\n\n};

    print sprintf("%5s, %s\t %s", '-i', '--input',  q{Входной файл (по умолчанию: domains.table.txt)}), "\n";
    print sprintf("%5s, %s\t %s", '-o', '--output', q{Выходной файл (по умолчанию: domains.digits.txt)}), "\n";
    print "\n";
    print sprintf("%6s %s\t %s", '', '--help', q{Показать эту справку и выйти}), "\n";
    print "\n";

    print qq{Пример: \n},
    q{ipton.pl -i ip.txt -o digits.txt}, "\n\n",
}

__END__
