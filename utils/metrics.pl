#!/usr/bin/perl -w

use strict;
use warnings;
use feature ':5.10';
use Getopt::Long 'HelpMessage';
use Data::Dumper;

my ( $file, $pattern );

GetOptions( 'file=s' => \$file ) or HelpMessage(1);

die "$0 requires the input filename argument (--file)\n" unless $file;

my $PATTERN = {
    'PORT' => 1731,
    'DST'  => "195.54.14.121"
};

my ( $line, $max, $cluster_id, $header, $fh );
my ( %clusters, %counters, %compromise, @keys, %result, %metrics );

open $fh, '<', $file or die $!;

$header = readline($fh);
undef $header;

while ( $line = <$fh> ) {

    $counters{'lines'}++;
    $line = &parse_csv_line($line);

    # 2 - dst, 3 - port, 8 - cluster_id
    $clusters{ $line->[8] }->{'elements'}++;
    $clusters{ $line->[8] }->{'bot'} ||= 0;

    if ( $PATTERN->{'PORT'} == $line->[3] && $PATTERN->{'DST'} eq $line->[2] )
    {
        $clusters{ $line->[8] }->{'bot'}++;
        $counters{'bot'}++;
    }
}

close $fh;

$max  = 0;
@keys = keys %clusters;
for (@keys) {

    # Количество ботов равно нулю
    next unless !!$clusters{$_}->{'bot'};

    # Ищем максимумальное кол-во ботов
    if ( $max < $clusters{$_}->{'bot'} ) {
        $cluster_id = $_;
        $max        = $clusters{$_}->{'bot'};
        undef %compromise;
    }

    # Несколько кластеров имеют максимум
    if ( $max == $clusters{$_}->{'bot'} ) {
        $compromise{$_} = $clusters{$_}->{'elements'};
    }
}

# Ищем кластер с наименьшим кол-вом
@keys = keys %compromise;
if ( @keys > 1 ) {
    $cluster_id = [ sort { $compromise{$a} > $compromise{$b} } @keys ]->[0];
}

# elements - суммарное кол-во записей в кластере
# bot - суммарное кол-во записей с ботом
# counter_lines - сумма всех записей
# counter_bots - сумма всех записей с ботом

$result{'cluster_id'}    = $cluster_id;
$result{'elements'}      = $clusters{$cluster_id}->{'elements'};
$result{'bot'}           = $clusters{$cluster_id}->{'bot'};
$result{'counter_lines'} = $counters{'lines'};
$result{'counter_bots'}  = $counters{'bot'};

$metrics{'TP'} = $result{'bot'};
$metrics{'TN'}
    = $result{'counter_lines'}
    - $result{'elements'}
    - ( $result{'counter_bots'} - $result{'bot'} );
$metrics{'FP'} = $result{'elements'} - $result{'bot'};
$metrics{'FN'} = $result{'counter_bots'} - $result{'bot'};

$metrics{'precision'} = $metrics{'TP'} / ( $metrics{'TP'} + $metrics{'FP'} );
$metrics{'recall'}    = $metrics{'TP'} / ( $metrics{'TP'} + $metrics{'FN'} );
$metrics{'f_measure'} = ( 2 * $metrics{'precision'} * $metrics{'recall'} )
    / ( $metrics{'recall'} + $metrics{'precision'} );

say sprintf( "True Positive: %d\tTrue Negative: %d",
    $metrics{'TP'}, $metrics{'TN'} );
say sprintf( "False Positive: %d\tFalse Negative: %d",
    $metrics{'FP'}, $metrics{'FN'} );
say sprintf( "\nPrecision: %.4f\tRecall: %.4f\t\nF-measure: %.4f",
    $metrics{'precision'}, $metrics{'recall'}, $metrics{'f_measure'} );

sub parse_csv_line {
    my $line = shift @_;

    chomp $line;
    $line =~ s/"//g;

    return split ';', $line if wantarray;
    return [ split ';', $line ];
}

