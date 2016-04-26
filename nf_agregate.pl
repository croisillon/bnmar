#!/usr/bin/perl

use Data::Dumper;
use Time::Piece ':override';
use Time::Seconds;
use feature ':5.10';
use PPNF;

select STDOUT;
$| = 1;

my $args = {@ARGV};

unless ( scalar @ARGV ) {
    print "For example: \n";
    print
        './nf_agregate.pl --file nf_traffic.txt --interval 2 --tmpdir /tmp --out /tmp/agregate.csv';
    print "\n";
    exit;
}

my $PCAP_IN       = $args->{'--file'}         || 'nf_traffic.txt';
my $TIME_INTERVAL = $args->{'--interval'}     || 1;
my $FILE_DIR      = $args->{'--tmpdir'}       || '/tmp';
my $OUT           = $args->{'--out'}          || '/tmp/agregate.csv';
my $CLEAN         = exists $args->{'--clean'} || 0;
my $FILE_EXT      = '.csv';
my $NEW_INTERVAL    = 0;
my $COUNT         = 0;

sub main {
    my ( $pcap,   $packet, $errbuf, $p,     $i, $line,  $j );
    my ( %header, %time,   %data,   %store, %v, @files, @fph );
    my ( $key, $min, $sec, $flags, $file, $fh );

    unlink glob &get_path('*') if $CLEAN;

    open $pcap, '<', $PCAP_IN or die $!;

    while ( $packet = <$pcap> ) {

        $p = &PPNF::parse_string( $packet, \%header );

        # Корректировка времени --
        # Текущее время пакета
        $time{'packet'} = localtime $header{'tv_sec'};
        ( $sec, $min ) = localtime $time{'packet'};

        # Убираем минуты и секунды
        $sec += ONE_MINUTE * $min;
        $time{'_packet'} = $time{'packet'} - $sec;

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
            $file
                = $COUNT . '_'
                . $time{'start'}->hour . '-'
                . $time{'finish'}->hour;

            $min = $TIME_INTERVAL;
            $sec = $time{'start'};

            push @{ $store{'files'} }, $file;

            while ( $min-- ) {
                push @{ $store{'intervals'}->[$COUNT] }, $sec->hms;

                $store{ $sec->epoch } = $file;

                $sec = $sec + ONE_HOUR;
            }

            ++$COUNT;

            say localtime(time)->hms
                . " - Time interval [".$time{'start'}->dmy('.').' '.$time{'start'}->hms.';'. $time{'finish'}->hms.')';

            $sec = $min = $file = undef;

            $NEW_INTERVAL = 1;
        } else {
        	$NEW_INTERVAL = 0;
        }

        # -- Корректировка времени

        $key = 0;
        map { $key += $_; } @{ $p->{'ip'} }{qw/src dst/},
            @{ $p->{'tcp'} }{qw/dst_port/};

        if ( $NEW_INTERVAL ) {
            $data{$key} = {};

            $data{$key}->{'bytes'} = 0;
            $data{$key}->{'ppf'} = 0;
            $data{$key}->{'bpp'} = 0;
            $data{$key}->{'bps'} = 0;
            $data{$key}->{'pps'} = 0;
            $data{$key}->{'duration'} = 0;
            $data{$key}->{'flows'} = 0;
        }

        map { $data{$key}->{$_} = $p->{'ip'}->{$_}; } qw/src dst/;
        map { $data{$key}->{$_} = $p->{'tcp'}->{$_}; }
            qw/dst_port/;

	    # Время начала сессии
	    ( $sec, $min ) = localtime $time{'packet'};
	    $sec += ONE_MINUTE * $min;
	    $data{$key}->{'s_time'} = $time{'packet'} - $sec;

		$data{$key}->{'bytes'} += $p->{'ip'}->{'len'};
		$data{$key}->{'ppf'} += $p->{'nf'}->{'ppf'};
		$data{$key}->{'bpp'} += $p->{'nf'}->{'bpp'};
		$data{$key}->{'bps'} += $p->{'nf'}->{'bps'};
		$data{$key}->{'pps'} += $p->{'nf'}->{'pps'};
		$data{$key}->{'flows'} += $p->{'nf'}->{'flows'};
		$data{$key}->{'duration'} += $p->{'nf'}->{'duration'};

        # Открываем файл к которому
        #   относится текущий интервал времени

        $file = $store{ $data{$key}->{'s_time'}->epoch };
        open( $fh, '>>', &get_path($file) );

        # Добавим заголовок
        if ( -z &get_path($file) ) {
            print $fh join( ",",
                qw/time src_ip src_port dst_ip dst_port flows ppf bpp bps/ )
                . "\n";
        }

        print $fh "\""
            . (
            join( "\", \"",
                $data{$key}->{'s_time'}->hms,
                &PPNF::toDotQuad( $data{$key}->{'src'} ),
                $data{$key}->{'src_port'},
                &PPNF::toDotQuad( $data{$key}->{'dst'} ),
                $data{$key}->{'dst_port'},
            	$data{$key}->{'flows'},
                $data{$key}->{'ppf'},
                sprintf( "%.2f", $data{$key}->{'bpp'} ),
                sprintf( "%.2f", $data{$key}->{'bps'} ) )
            ) . "\"\n";
        close $fh;
        undef $fh;

        # Убираем ненужное
        undef $data{$key};
        delete $data{$key};
    }

    @files = @{ $store{'files'} };

    for ( $j = 0; $j < scalar @files; ++$j ) {

        next unless -e &get_path( $files[$j] );

        say localtime(time)->hms
            . qq{ - Starting agregate file }
            . $files[$j];
        open $fh, '<', &get_path( $files[$j] ) or die $!;

        undef %data;

        $i = 0;
        while ( $line = <$fh> ) {

            # Отбрасываем первую строчку
            if ( !$i ) { ++$i; next; }

            # Убираем лишние знаки
            $line =~ s/\n$//;
            $line =~ s/^\"|\"$//g;
            $line =~ s/\s*//g;

            # Получаем поля
            (   $v{'time'}, $v{'src'}, $v{'srcp'}, $v{'dst'},
                $v{'dstp'}, $v{'flows'}, $v{'ppf'}, $v{'bpp'},  $v{'bps'}
            ) = split /\",\"/, $line;

            next unless $v{'dstp'} =~ m/\d/;

            # Ключ из ip_src + ip_dst + port_dst
            $key = $v{'src'} . $v{'dst'} . $v{'dstp'};

            # Сохраняем ключи
            unless ( defined $store{'keys_h'}->{$key} ) {

                # Массив ключей необходим для уникального набора
                # Тем самым исключив повторные ключи
                push @{ $store{'keys_a'} }, $key;

                # Хеш необходим что бы записать полный набор ключей
                $store{'keys_h'}->{$key} = 1;
            }
            
            # О каждом потоке собираем информацию
            # Адрес источника, адрес и порт назначения
            $data{$key}->{'src'}  = $v{'src'};
            $data{$key}->{'dst'}  = $v{'dst'};
            $data{$key}->{'dstp'} = $v{'dstp'};

            # Информацию о критериях потока агрегируем в массив
            push @{ $data{$key}->{'ppf'} }, $v{'ppf'};
            push @{ $data{$key}->{'bpp'} }, $v{'bpp'};
            push @{ $data{$key}->{'bps'} }, $v{'bps'};

            # Подсчитываем количество схожих потоков в интервале времени
            if ( $data{$key}->{'fph'}->{ $v{'time'} } ) {
                $data{$key}->{'fph'}->{ $v{'time'} } += $v{'flows'};
            }
            else {
                $data{$key}->{'fph'}->{ $v{'time'} } = $v{'flows'};
            }

        }
        close $fh;
        undef $fh;

        # Обрабатываем посчитанные данные
        open $fh, '>>', $OUT or die $!;

        # Если итерация первая, добавим заголовки
		unless ( $j ) {
	        print $fh join ',', map { qq{"$_"} } qw/src_ip dst_ip dst_port fph ppf bpp bps/;
	        print $fh "\n";
    	}

        while ( $key = shift @{ $store{'keys_a'} } ) {

            # Достаем информацию об агрегированных потоках
            (   $v{'fph'}, $v{'src'}, $v{'dst'}, $v{'dstp'},
                $v{'ppf'}, $v{'bpp'}, $v{'bps'}
            ) = @{ $data{$key} }{qw/fph src dst dstp ppf bpp bps/};

            # Извлекаем fph
            @fph = ();
            map { push @fph, ( $v{'fph'}->{$_} || '0' ); }
                @{ $store{'intervals'}->[$j] };

            # Готовим данные для записи
            $v{'ppf'} = join ',', @{ $v{'ppf'} };
            $v{'bpp'} = join ',', @{ $v{'bpp'} };
            $v{'bps'} = join ',', @{ $v{'bps'} };
            $v{'fph'} = join ',', @fph;

            print $fh join ',',
                map {qq{"$_"}} @{ \%v }{qw/src dst dstp fph ppf bpp bps/};

            print $fh "\n";

        }

        close $fh;
        undef $fh;

        $store{'keys_h'} = undef;
        $store{'keys_a'} = undef;
        undef %v;

        say localtime(time)->hms . qq{ - End agregate file } . $files[$j];

    }

}

sub get_path {
    return $FILE_DIR . '/' . (shift) . $FILE_EXT;
}

&main();

__END__
