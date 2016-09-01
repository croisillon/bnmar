#!/usr/bin/perl

use strict;
use warnings;
use Data::Dumper;
use feature ':5.10';
use File::Spec;
use Getopt::Long 'HelpMessage';

my ( $DIR, $OUT, $SUM );

GetOptions(
    'dir=s' => \$DIR,
    'out=s' => \$OUT,
    'sum'   => \$SUM,
    'help'  => sub { HelpMessage(0) }
) or HelpMessage(1);

die "$0 requires the input dir argument (--dir)\n"    unless $DIR;
die "$0 requires the input output argument (--out)\n" unless $OUT;

my ( %data, @cols, %ips, $file );

unless ($SUM) {

    my @files = glob File::Spec->catdir( $DIR, '*' );

    while ( $file = shift @files ) {
        next unless -f $file;

        push @cols, [ File::Spec->splitdir($file) ]->[-1];
        my $record = $data{ $cols[-1] } = {};

        open my $fh, '<', $file or die $!;

        while (<$fh>) {

            next unless $_ =~ m/\d/;

            $_ = [ split ';' ]->[2];

            $_ =~ s/"//g;

            $ips{$_} = 1;

            $record->{$_} ||= 1;
            $record->{$_} += 1;

        }

        close $fh;
        undef $fh;
    }

    my $ip;
    my @ips = keys %ips;

    open my $newfile, '>', $OUT;
    say $newfile join( ';', 'IP', @cols );

    while ( $ip = shift @ips ) {
        say $newfile join( ';', $ip, @{ find($ip) } );
    }

}
else {

    my ( @clusts, %ips, $file, @files );
    my @found = glob File::Spec->catfile( $DIR, '*' );

    my ( @arr, @headers, %strings, %maxvalue );
    for $file (@found) {
        next unless -f $file;

        push @files, $file;
        open my $fh, '<', $file or die $!;

        while ( my $line = <$fh> ) {
            unless ( $line =~ m/^\d/ ) {
                push @headers, [ split ';', $line ];
                next;
            }

            @arr = split ';', $line;
            for ( my $i = 1; $i < @arr - 1; ++$i ) {

                $maxvalue{$file}->{ $arr[0] } ||= [ 0, 'unknown' ];
                my $it = $maxvalue{$file}->{ $arr[0] }->[0];

                if ( $arr[$i] ) {
                    $maxvalue{$file}->{ $arr[0] } = [ $arr[$i], $headers[-1]->[$i] ]
                        if $it < $arr[$i];
                }
            }

            # exit;
            $ips{ $arr[0] } ||= 0;
            $ips{ $arr[0] } += 1;

            $strings{$file}->{ $arr[0] } = $line;
        }

        close $fh;
        undef $fh;
    }

    my @union = grep { $ips{$_} == scalar @files; } keys %ips;

    my ( $filename, $ip, $value );
    for $file (@files) {
        next unless -f $file;

        $filename = join( '.', File::Spec->splitdir($file), 'csv' );
        $filename = File::Spec->catfile( $OUT, $filename );
        $value = $strings{$file};

        open my $fh, '>', $filename or die $!;

        print $fh join( ';', @{ shift @headers } );
        for (@union) {
            print $fh $value->{$_} if $value->{$_};
        }

        close $fh;
        undef $fh;
    }

    my @str;
    open my $summary, '>', File::Spec->catfile( $OUT, 'result.corr.csv' ) or die $!;
    say $summary join ';', 'ip', @files;
    for my $ip (@union) {

        @str = ();
        for $file (@files) {
            push @str, @{$maxvalue{$file}->{$ip}};
        }

        say $summary join ';', $ip, @str;
    }
    close $summary;
}

sub find {
    my ($ip) = @_;

    my @numbers;
    for (@cols) {
        push @numbers, $data{$_}->{$ip} || '';
    }

    return \@numbers;
}

__END__
