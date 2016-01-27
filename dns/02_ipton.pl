#!/usr/bin/perl

use common::sense;
use Getopt::Long 'HelpMessage';
use Socket qw/inet_aton/;

select STDOUT;
$| = 1;

my ( $file, $out );

GetOptions(
    'file=s' => \$file,
    'out=s'  => \$out,
    'help'   => sub { HelpMessage(0) }
) or HelpMessage(1);

# Defaults
$file = $file || 'domains.table.txt';
$out  = $out  || 'domains.digits.txt';

die qq{File "$file" is not found\n}   unless -e $file;
die qq{FIle "$file" cannot be read\n} unless -r $file;

my ( $in_fh, $out_fh );

open $in_fh,  '<', $file or die $! . "\n";
open $out_fh, '>', $out  or die $! . "\n";

say 'Processed...';
for (<$in_fh>) {
    if ( $_ =~ m/^\D/ ) { next; }
    map {
        chomp $_;
        print $out_fh ( unpack 'N', &inet_aton($_) ), "\n";
    } split ',', $_;
}
say 'Done';

close($in_fh);
close($out_fh);

__END__

=encoding utf8

=head1 NAME

IP address to Number

=head1 SYNOPSIS

 ipton.pl [КЛЮЧ]

 -f, --file        Входной файл (по умолчанию: domains.table.txt)
 -o, --out         Выходной файл (по умолчанию: domains.digits.txt)

     --help        Показать эту справку и выйти

=head2 Примеры

 ipton.pl -f ip.txt -o digits.txt

=head2 Формат входного файла

=over

=item #adobe.com

=item 192.150.16.117

=item #leboncoin.fr

=item 193.164.197.82,193.164.196.82

=item #espn.go.com

=item 199.181.133.61

=item ...

=item ------- OR -------

=item 111.206.227.118,211.152.123.224

=item 188.125.93.100,188.125.93.101

=item 188.125.93.100,188.125.93.101

=item 104.156.81.194,23.235.37.194,104.156.85.194,23.235.33.194

=item ...

=back

=head2 Формат выходного файла

=over

=item 1875829622

=item 3549985760

=item 3162332516

=item 3162332517

=item 3162332516

=item 3162332517

=item 1755075010

=item 401286594

=item 1755076034

=item 401285570

=item ...

=back

=head1 AUTHOR

Denis Lavrov (C<diolavr@gmail.com>)

=cut
