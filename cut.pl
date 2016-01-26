#!/usr/bin/perl

use Net::Pcap;
use Data::Dumper;
use Time::Piece ':override';
use Time::Seconds;
use common::sense;
use PP;

select STDOUT;
$| = 1;

my $args = {@ARGV};

unless ( scalar @ARGV ) {
    print "For example: \n";
    print
        './cut.pl --file traffic.pcap --interval 2 --todir /home/user/agreagate';
    print "\n";
    exit;
}

my $PCAP_IN       = $args->{'--file'}         || 'traffic.pcap';
my $TIME_INTERVAL = $args->{'--interval'}     || 1;
my $FILE_DIR      = $args->{'--todir'}        || '/tmp';
my $CLEAN         = exists $args->{'--clean'} || 0;
my $FILE_EXT      = '.csv';
my $BLOCK_TIME    = 0;
my $COUNT         = 0;

sub main {
    my ( $pcap,   $packet, $errbuf,  $p );
    my ( %header, %time,   %journal, %store );

    unlink glob &get_path('*') if $CLEAN;

    $pcap = Net::Pcap::pcap_open_offline( $PCAP_IN, \$errbuf )
        or die("error reading pcap file: $errbuf");

    my ( $key, $flags, $i, $min, $sec, $file );

    $i = 0;
    while ( $packet = Net::Pcap::pcap_next( $pcap, \%header ) ) {
        ++$i;

        $p = &PP::parse_packet( $packet, \%header );

        # Корректировка времени --
        # Текущее время пакета
        $time{'packet'} = localtime $header{'tv_sec'};
        ( $sec, $min ) = localtime $time{'packet'};

        # Убираем минуты и секунды
        $sec += ONE_MINUTE * $min;
        $time{'_packet'} = $time{'packet'} - $sec;

        if ( !$BLOCK_TIME ) {

            # (1) Конечный интервал еще не объект Time::Piece
            # или
            # (2) Время пакета больше конечного интервала
            if (   ( ref $time{'finish'} ne 'Time::Piece' )
                || ( $time{'packet'}->epoch >= $time{'finish'}->epoch ) )
            {

                # Начальный интервал не объект Time::Piece
                if ( ref $time{'start'} ne 'Time::Piece' ) {

                    # (1)
                    $time{'start'} = $time{'_packet'};
                }
                else {
                    # (2)
                    $time{'start'} = $time{'finish'};
                }

                # Определяем конечный интервал
                $time{'finish'}
                    = $time{'start'} + ( ONE_HOUR * $TIME_INTERVAL );

                # Решает проблему нормализации
                # Когда пакеты одного интервала были в файлах другого интервала
                # Привязка каждого часа временного интервала к определенному файлу
                $file = $time{'start'}->hour . '-' . $time{'finish'}->hour;
                $min  = $TIME_INTERVAL;
                $sec  = $time{'start'};

                while ( $min-- ) {
                    $store{ $sec->epoch } = $COUNT . '_' . $file;
                    $sec = $sec + ONE_HOUR;
                }

                ++$COUNT;

                say localtime(time)->hms
                    . " - Set start interval: "
                    . $time{'start'}->hms;
                say localtime(time)->hms
                    . " - Set finish interval: "
                    . $time{'finish'}->hms;

                $sec = $min = $file = undef;
            }
        }

        # -- Корректировка времени

        $key = 0;
        map { $key += $_; } @{ $p->{'ip'} }{qw/src dst/},
            @{ $p->{'tcp'} }{qw/dst_port src_port/};

        $flags = $p->{'tcp'}->{'flags'};

        if ( $flags == TCP_FLAG_SYN ) {

            # Блокируем изменение времени
            # Пока сессия не будет закончена
            $BLOCK_TIME = 1;

            $journal{$key} = {};

            map { $journal{$key}->{$_} = $p->{'ip'}->{$_}; } qw/src dst/;
            map { $journal{$key}->{$_} = $p->{'tcp'}->{$_}; }
                qw/dst_port src_port/;

            $journal{$key}->{'SYN'} = 1;
            $journal{$key}->{'FIN'} ||= 0;
            $journal{$key}->{'ACK'} ||= 0;

            # Время начала сессии
            ( $sec, $min ) = localtime $time{'packet'};
            $sec += ONE_MINUTE * $min;
            $journal{$key}->{'s_time'} = $time{'packet'} - $sec;

            # Количество байт в потоке
            $journal{$key}->{'bytes'} ||= 0;

            # ppf - Количество пакетов в потоке
            # bpp - AVG(байт в пакетах)
            # bps - AVG(байт в секунду)
            $journal{$key}->{'ppf'} ||= 0;
            $journal{$key}->{'bpp'} ||= 0;
            $journal{$key}->{'bps'} ||= 0;

        }

        if ( defined $journal{$key}->{'SYN'} ) {

            # Сбор данных сессии --
            $journal{$key}->{'bytes'} += $p->{'ip'}->{'len'};
            $journal{$key}->{'ppf'}   += 1;

            # -- Сбор данных сессии

            # ACK, SYN
            $journal{$key}->{'SYN'} = 2
                if $flags == ( TCP_FLAG_ACK + TCP_FLAG_SYN );

            # ACK, FIN or FIN, PSH, ACK
            if (   ( $flags & TCP_FLAG_FIN != 0 )
                && ( $flags & TCP_FLAG_ACK != 0 ) )
            {
                $journal{$key}->{'FIN'} = 1 if !$journal{$key}->{'FIN'};
                $journal{$key}->{'FIN'} = 2 if $journal{$key}->{'FIN'} == 1;
            }
            elsif ( $journal{$key}->{'FIN'} > 0 ) {
                $journal{$key}->{'ACK'} += 1;
            }

            $flags = 0;
            map { $flags += $_ } @{ $journal{$key} }{qw/SYN FIN ACK/};

            if ( $flags == 6 ) {

                # Время окончания сессии
                # Из последнего ACK-пакета
                $journal{$key}->{'e_time'} = $time{'packet'};

                # Продолжительность сессии
                $journal{$key}->{'duration'}
                    = $journal{$key}->{'e_time'} - $journal{$key}->{'s_time'};
                $journal{$key}->{'duration'} ||= 1;

                $journal{$key}->{'bpp'}
                    = $journal{$key}->{'bytes'} / $journal{$key}->{'ppf'};

                $journal{$key}->{'bps'} = $journal{$key}->{'bytes'}
                    / $journal{$key}->{'duration'};

                # Открываем файл к которому относится
                #   текущий интервал времени
                $file = $store{ $journal{$key}->{'s_time'}->epoch };
                open( my $fh, '>>', &get_path($file) );

                # Добавим заголовок
                if ( -z &get_path($file) ) {
                    print $fh join( ",",
                        qw/time src_ip src_port dst_ip dst_port ppf bpp bps/ )
                        . "\n";
                }

                print $fh "\""
                    . (
                    join( "\", \"",
                        $journal{$key}->{'s_time'}->hms,
                        &PP::toDotQuad( $journal{$key}->{'src'} ),
                        $journal{$key}->{'src_port'},
                        &PP::toDotQuad( $journal{$key}->{'dst'} ),
                        $journal{$key}->{'dst_port'},
                        $journal{$key}->{'ppf'},
                        sprintf( "%.2f", $journal{$key}->{'bpp'} ),
                        sprintf( "%.2f", $journal{$key}->{'bps'} ) )
                    ) . "\"\n";
                close $fh;

                # Убираем ненужное
                undef $journal{$key};
                delete $journal{$key};

                $BLOCK_TIME = 0;
            }

        }
        else {
            undef $journal{$key};
            delete $journal{$key};
        }

    }
}

sub get_path {
    return $FILE_DIR . '/' . (shift) . $FILE_EXT;
}

&main();

__END__
