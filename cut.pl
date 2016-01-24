#!/usr/bin/perl

use warnings;
use strict;
use Net::Pcap;
use Data::Dumper;
use Time::Piece ':override';
use Time::Seconds;
use common::sense;
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
            say $t->epoch;
            $journal{ $t->epoch } = { t => $t->epoch };
        }

        # Делаем уникальный ключ
        $key = 0;
        map { $key += $_; } @{ $p->{'ip'} }{qw/src dst/},
            @{ $p->{'tcp'} }{qw/dst_port src_port/};

        $flags = $p->{'tcp'}->{'flags'};

# При начале сессии инициализируем переменные
        if ( $flags == TCP_FLAG_SYN ) {
            $journal{$key} = {};

            $journal{$key}->{'SYN'} = 1;
            $journal{$key}->{'FIN'} = 0;
            $journal{$key}->{'ACK'} = 0;

            $journal{$key}->{'bytes'} ||= 0;
            $journal{$key}->{'ppf'}   ||= 0;

            $journal{$key}->{'time'} = ( localtime $header{'tv_sec'} )->epoch;
            $journal{$key}->{'src'}->{'ip'}   = $p->{'ip'}->{'src'};
            $journal{$key}->{'dst'}->{'ip'}   = $p->{'ip'}->{'dst'};
            $journal{$key}->{'src'}->{'port'} = $p->{'tcp'}->{'src_port'};
            $journal{$key}->{'dst'}->{'port'} = $p->{'tcp'}->{'dst_port'};
        }

        # SYN
        if ( defined $journal{$key}->{'SYN'} ) {

            # Количество байт в потоке
            $journal{$key}->{'bytes'} += $p->{'ip'}->{'len'};

            # Количество пакетов в потоке
            $journal{$key}->{'ppf'} += 1;

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

                $journal{$key}->{'time'}
                    = ( localtime $header{'tv_sec'} )->epoch
                    - $journal{$key}->{'time'};

                $journal{$key}->{'time'} ||= 1;

                # Среднее число байт в пакетах
                $journal{$key}->{'bpp'}
                    = $journal{$key}->{'bytes'} / $journal{$key}->{'ppf'};

              # Среднее количество байт в секунду
                $journal{$key}->{'bps'}
                    = $journal{$key}->{'bytes'} / $journal{$key}->{'time'};

                open( my $fh, '>>', &report_path(01) );

         # Если отчет пустой, добавим заголовок
                if ( -z &report_path(01) ) {
                    print $fh "\""
                        . (
                        join "\", \"",
                        qw/time src_ip src_port dst_ip dst_port ppf bpp bps/
                        ) . "\"\n";
                }

                print $fh "\""
                    . (
                    join( "\", \"",
                        $t->hms,
                        &PP::toDotQuad( $journal{$key}->{'src'}->{'ip'} ),
                        $journal{$key}->{'src'}->{'port'},
                        &PP::toDotQuad( $journal{$key}->{'dst'}->{'ip'} ),
                        $journal{$key}->{'dst'}->{'port'},
                        $journal{$key}->{'ppf'},
                        sprintf( "%.2f", $journal{$key}->{'bpp'} ),
                        sprintf( "%.2f", $journal{$key}->{'bps'} ) )
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

