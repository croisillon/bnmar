#!/usr/bin/perl

use warnings;
use strict;
use Data::Dumper;
use Time::Piece ':override';
use Time::Seconds;
use feature ':5.10';
use IO::Handle;
use Getopt::Long 'HelpMessage';
use File::Spec;
use JSON;
use PP qw/toDotQuad parse_netflow/;

STDOUT->autoflush(1);
local $ENV{TZ} = 'UTC-2';

my ( $INPUT_FILE, $OUT_FILE, $VERBOSE, $TIME_INTERVAL );
my ( $TMP_DIR, $TMP_EXT );

$TIME_INTERVAL = 1;

$TMP_DIR = '/tmp';
$TMP_EXT = '.json';

GetOptions(
    'file=s'     => \$INPUT_FILE,
    'out=s'      => \$OUT_FILE,
    'tmpdir=s'   => \$TMP_DIR,
    'interval=s' => \$TIME_INTERVAL,
    'verbose'    => \$VERBOSE,
    'help'       => sub { HelpMessage(0) }
) or HelpMessage(1);

my (%files);    # Glabal variable

fragmentation($INPUT_FILE);

say sprintf( "[%s]: Agregation has been started", localtime->hms );

open my $out_fh, '>', $OUT_FILE or die $!;
$out_fh->autoflush(1);
say $out_fh _csv_string(qw/src_ip dst_ip dst_port fph ppf bpp bps/);

my ( @keys, $data, %out, $intervals );
for my $file ( @{ $files{'fragments'} } ) {

    $intervals = shift @{ $files{'intervals'} };

    next unless -e $file;

    say sprintf( "[%s]: Agregating file %s", localtime->hms, $file );

    $data = calculate_data($file);

    @keys = keys %{$data};
    for my $key (@keys) {

        %out = %{ $data->{$key} };

        $out{'fph'} = [];
        for (@$intervals) {
            push @{ $out{'fph'} }, sprintf( '%d', $data->{$key}->{'fph'}->{$_} || 0 );
        }

        $out{'fph'} = sprintf( _fph_format( $intervals ), @{ $out{'fph'} } );

        $out{$_} = join ',', @{ $out{$_} } for (qw/ppf bpp pps bps/);

        say $out_fh _csv_string( @{ \%out }{qw/src dst dst_port fph ppf bpp bps/} );
    }

}

close $out_fh;

say sprintf( "[%s]: Agregation has been completed", localtime->hms );

sub _fph_format {
    my ($a) = @_;
    my @f;
    push @f, '%d' for @{$a};
    return join ',', @f;
}

sub _csv_string {
    join ';', map {qq{"$_"}} @_;
}

sub _key { $_[0]->{'src'} . $_[0]->{'dst'} . $_[0]->{'dst_port'} }

sub calculate_data {
    my ($file) = @_;
    my ( %data, $ref, $line, $key );

    open my $file_fh, '<', $file or die $!;

    while ( $line = <$file_fh> ) {

        $ref = decode_json($line);

        $key = _key($ref);

        $data{$key}->{$_} = $ref->{$_} for (qw/src dst dst_port/);

        push @{ $data{$key}->{$_} }, $ref->{$_} for (qw/ppf bpp pps bps/);

        $data{$key}->{'fph'}->{ $ref->{'time'} } ||= 0;
        $data{$key}->{'fph'}->{ $ref->{'time'} } += 1;

    }

    close $file_fh;

    return \%data;
}

sub fragmentation {
    my ($input) = @_;
    my ( $str, $interval, %header, %data );

    say sprintf( "[%s]: Fragmentation has been started", localtime->hms );

    # Очистка временного каталога
    unlink glob temp_dir( '*' . $TMP_EXT );

    # Установка окончания интервала по нулям
    $interval->{'end'} = localtime(0);

    open my $input_fh, '<', $input or die $!;

    while ( $str = <$input_fh> ) {
        $str = PP::parse_netflow( $str, \%header );

        $str->{'timestamp'} = get_oclock( $header{'tv_sec'} );

        if ( $header{'tv_sec'}->epoch >= $interval->{'end'}->epoch ) {

            $interval = set_interval( $interval, $header{'tv_sec'} );

            tie_interval_with_file($interval);

            say sprintf(
                '[%s]: Interval: %s - %s',
                localtime(time)->hms,
                $interval->{'start'}->hms,
                $interval->{'end'}->hms
            );
        }

        $data{'time'}     = get_oclock( $header{'tv_sec'} )->hms;
        $data{'src'}      = &PP::toDotQuad( $str->{'src'} );
        $data{'dst'}      = &PP::toDotQuad( $str->{'dst'} );
        $data{'src_port'} = $str->{'src_port'};
        $data{'dst_port'} = $str->{'dst_port'};

        $data{'bytes'}    = $str->{'bytes'};
        $data{'duration'} = $str->{'duration'};

        $data{'ppf'} = $str->{'packets'};
        $data{'bpp'} = sprintf( "%.2f", $data{'bytes'} / $data{'ppf'} );
        
        if ( $data{'duration'} > 0 ) {
        	$data{'pps'} = sprintf( "%.2f", $data{'ppf'} / $data{'duration'} );
        	$data{'bps'} = sprintf( "%.2f", $data{'bytes'} / $data{'duration'} );
    	} else {
    		$data{'pps'} = sprintf( "%.2f", 0);
    		$data{'bps'} = sprintf( "%.2f", 0);
    	}

        delete $data{$_} for (qw/bytes duration/);

        open my $file_fh, '>>', $files{ $str->{'timestamp'}->epoch } or die $!;
        $file_fh->autoflush(1);
        say $file_fh encode_json( \%data );
        close $file_fh;

        %data = ();
    }

    close $input_fh;

    say sprintf( "[%s]: Fragmentation has been comleted", localtime->hms );

    return \%files;
}

sub tie_interval_with_file {
    my ($time) = @_;

    my ( $start, $end ) = @{$time}{qw/start end/};

    # Список файлов для дальнейшей агрегации
    $files{'fragments'} ||= [];
    $files{'intervals'} ||= [];

    my $count = @{ $files{'fragments'} };

    my $filename = $count . ( $start->hour ) . ( $end->hour ) . $TMP_EXT;

    push @{ $files{'fragments'} }, temp_dir($filename);

    my ( $i, $interval ) = ( $TIME_INTERVAL, $start );
    while ( $i-- ) {

        # Сохраним все входящие интервалы
        push @{ $files{'intervals'}->[$count] }, $interval->hms;

        # Каждый час интервала связываем с одним файлом
        $files{ $interval->epoch } = temp_dir($filename);

        $interval = $interval + ONE_HOUR;
    }

    return;
}

sub temp_dir { File::Spec->catfile( $TMP_DIR, @_ ) }

sub set_interval {
    my ( $int, $time ) = @_;

    my ( $start, $end ) = @{$int}{qw/start end/};

    $start = $start ? $end : get_oclock($time);

    $end = $start + ( ONE_HOUR * $TIME_INTERVAL );

    return {
        'start' => $start,
        'end'   => $end
    };
}

sub get_oclock {
    my ($time) = @_;

    my ( $sec, $min ) = localtime $time;
    $sec += ONE_MINUTE * $min if $min;

    return localtime($time) - $sec;
}

__END__
