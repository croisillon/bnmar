#!/usr/bin/perl -w

use strict;
use warnings;
use feature ':5.10';
use Getopt::Long 'HelpMessage';
use Data::Dumper;

my ( $file, $pattern, $out, $column );

$column = 8;
GetOptions( 
    'file=s' => \$file,
    'out=s' => \$out,
    'column=s' => \$column,
    'pattern=s' => \$pattern,
) or HelpMessage(1);

die "$0 requires the input filename argument (--file)\n" unless $file;
die "$0 requires the input output argument (--out)\n" unless $out;
die "$0 requires the input pattern argument (--pattern) example: --pattern 192.168.1.5:7754 \n" unless $pattern;

my $tmp = {};
($tmp->{'DST'}, $tmp->{'PORT'}) = split ':', $pattern;

my ( $line, $max, $cluster_id, $header, $fh );
my ( %clusters, %counters, %compromise, @keys, %result, %metrics );

open $fh, '<', $file or die $!;

$header = readline($fh);
undef $header;

while ( $line = <$fh> ) {

    $counters{'lines'}++;
    $line = &parse_csv_line($line);

    # 2 - dst, 3 - port, $column - cluster_id
    $clusters{ $line->[$column] }->{'elements'}++;
    $clusters{ $line->[$column] }->{'bot'} ||= 0;

    if ( $tmp->{'PORT'} == $line->[3] && $tmp->{'DST'} eq $line->[2] )
    {
        $clusters{ $line->[$column] }->{'bot'}++;
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


if ( defined $cluster_id ) {
    open $fh, '>', $out or die $!;

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

    say $fh sprintf(
        "Lines in file: %d\tBot's traffic: %d\n",
        $result{'counter_lines'},
        $result{'counter_bots'}
    );
    say $fh sprintf( "Cluster id: %d\n", $result{'cluster_id'} );
    say $fh sprintf( "Count elements: %d\t Count bot: %d\n",
        $result{'elements'}, $result{'bot'} );
    say $fh sprintf( "True Positive: %d\tTrue Negative: %d",
        $metrics{'TP'}, $metrics{'TN'} );
    say $fh sprintf( "False Positive: %d\tFalse Negative: %d\n",
        $metrics{'FP'}, $metrics{'FN'} );
    say $fh sprintf( "Precision: %.4f\tRecall: %.4f\t\nF-measure: %.4f",
        $metrics{'precision'}, $metrics{'recall'}, $metrics{'f_measure'} );

    close $fh;
}

sub parse_csv_line {
    my $line = shift @_;

    chomp $line;
    $line =~ s/"//g;

    return split ';', $line if wantarray;
    return [ split ';', $line ];
}

