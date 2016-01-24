#!/usr/bin/perl

use warnings;
use strict;
use Net::Pcap;
use Data::Dumper;
use Time::Piece ':override';
use Time::Seconds;
use PP;

select STDOUT;
$| = 1;

use constant PCAP_IN      => 'filtered.pcap';
use constant REPORT_EXT   => '.csv';
use constant REPORT_DIR   => 'reports';
use constant REPORT_CLEAN => 1;

sub main {
    my ( $pcap, $packet, $errbuf, %header, $p );

    # Убрать старые отчеты перед началом работы
    unlink glob &report_path('*') if REPORT_CLEAN;

    # Открываем pcap для создания отчета
    $pcap = Net::Pcap::pcap_open_offline( PCAP_IN, \$errbuf )
        or die("error reading pcap file: $errbuf");

    my ( %journal, $sec, $min, $flags, $bytes, $key, $syn_ip, $t );

    while ( $packet = Net::Pcap::pcap_next( $pcap, \%header ) ) {

        $p = &PP::parse_packet( $packet, \%header );

        # Получаем время в пакете
        # Преобразуем время на начало часа
        ( $sec, $min ) = localtime $header{'tv_sec'};

        $min *= ONE_MINUTE;
        $t = localtime $header{'tv_sec'} - $min - $sec;

        # Запись в журнал
        unless ( exists $journal{ $t->epoch } ) {
            $journal{ $t->epoch } = {
                t   => $t->epoch,
                fph => 0
            };
        }

        # Делаем уникальный ключ
        $key = 0;
        map { $key += $_; } @{ $p->{'ip'} }{qw/src dst/},
            @{ $p->{'tcp'} }{qw/dst_port src_port/};

        $flags = $p->{'tcp'}->{'flags'};

        # При начале сессии инициализируем переменные
        if ( $flags == TCP_FLAG_SYN ) {
            ++$journal{ $t->epoch }->{'fph'};
            $journal{$key} = {};

            $journal{$key}->{'SYN'} = 1;
            $journal{$key}->{'FIN'} = 0;
            $journal{$key}->{'ACK'} = 0;
            $journal{$key}->{'bytes'}->{'out'}   ||= 0;
            $journal{$key}->{'bytes'}->{'in'}    ||= 0;
            $journal{$key}->{'packets'}->{'out'} ||= 0;
            $journal{$key}->{'packets'}->{'in'}  ||= 0;
            $journal{$key}->{'timer'}->{'start'}
                = ( localtime $header{'tv_sec'} )->epoch;
            $journal{$key}->{'src'} = $p->{'ip'}->{'src'};
            $journal{$key}->{'dst'} = $p->{'ip'}->{'dst'};
            $syn_ip                 = $p->{'ip'}->{'src'};
        }

        # SYN
        if ( defined $journal{$key}->{'SYN'} ) {

            if ( $p->{'ip'}->{'src'} eq $syn_ip ) {
                # Количество переданных байт LAN -> INTERNET
                $journal{$key}->{'bytes'}->{'out'} += $p->{'ip'}->{'len'};
                ++$journal{$key}->{'packets'}->{'out'};
            }
            else {
                # Количество принятых байт INTERNET -> LAN
                $journal{$key}->{'bytes'}->{'in'} += $p->{'ip'}->{'len'};
                ++$journal{$key}->{'packets'}->{'in'};
            }

            # ACK, SYN
            $journal{$key}->{'SYN'} = 2
                if $flags == ( TCP_FLAG_ACK + TCP_FLAG_SYN );

            # ACK, FIN or FIN, PSH, ACK
            if (   $flags == ( TCP_FLAG_FIN + TCP_FLAG_ACK )
                || $flags == ( TCP_FLAG_PSH + TCP_FLAG_FIN + TCP_FLAG_ACK ) )
            {
                $journal{$key}->{'FIN'} = 1 if !$journal{$key}->{'FIN'};
                $journal{$key}->{'FIN'} = 2 if $journal{$key}->{'FIN'} == 1;
            }
            elsif ( $journal{$key}->{'FIN'} > 0 ) {
                ++$journal{$key}->{'ACK'};
            }

        }

        if ( defined $journal{$key}->{'SYN'} ) {

            $flags
                = $journal{$key}->{'SYN'}
                + $journal{$key}->{'FIN'}
                + $journal{$key}->{'ACK'};

            if ( $flags == 6 ) {

            	# Сохраняем время последнего пакета
                $journal{$key}->{'timer'}->{'end'}
                    += ( localtime $header{'tv_sec'} )->epoch;

                # Количество пакетов в потоке
                $journal{ $t->epoch }->{'ppf'}
                    += $journal{$key}->{'packets'}->{'out'}
                    + $journal{$key}->{'packets'}->{'in'};

                # Количество байт в потоке
                $bytes = $journal{$key}->{'bytes'}->{'out'}
                    + $journal{$key}->{'bytes'}->{'in'};

                # Среднее число байт в пакетах
                $journal{ $t->epoch }->{'bpp'}
                    += $bytes / $journal{ $t->epoch }->{'ppf'};

                # Интервал времени за который прошел весь поток (в сек)
                $sec
                    = (   $journal{$key}->{'timer'}->{'end'}
                        - $journal{$key}->{'timer'}->{'start'} )
                    || 1;

                # Среднее количество байт в секунду
                $journal{ $t->epoch }->{'bps'} += $bytes / $sec;

                # Запишем в отчет
                open my $fh, '>>', &report_path( $t->epoch );

                # Если отчет пустой, добавим заголовок
                if ( -z &report_path( $t->epoch ) ) {
                    print $fh "\""
                        . (
                        join "\", \"",
                        qw/src_ip dst_ip ppf bytes_out bytes_in duration/
                        ) . "\"\n";
                }

                print $fh "\""
                    . (
                    join( "\", \"",
                        $journal{$key}->{'src'},
                        $journal{$key}->{'dst'},
                        $journal{ $t->epoch }->{'ppf'},
                        $journal{$key}->{'bytes'}->{'out'},
                        $journal{$key}->{'bytes'}->{'in'},
                        $sec )
                    ) . "\"\n";
                close $fh;

                # Убираем ненужное
                undef $journal{$key};
                delete $journal{$key};
            }

        }
        else {
            undef $journal{$key};
            delete $journal{$key};
        }

    }

}

&main();

sub report_path {
    return REPORT_DIR . '/' . (shift) . REPORT_EXT;
}

__END__

