#!/usr/bin/perl -w

use strict;
use warnings;
use feature ':5.10';
use File::Spec::Functions qw(catfile);
use File::Path qw(make_path);

my $exp = '07';
my $ip = 251;

my ($algh, $interval);
# , 'dbscan', 'em'
my @algs = ('xmeans', 'dbscan');
my ($input_dir, $output_dir);

# for $algh ( @algs ) {
# 	for $interval (2,4,6,8,10,24) {
# 		$input_dir = catfile($exp, $ip, '01_clustering', $algh);
# 		# system "utils/whois_csv.pl --in $input_dir/int$interval.csv --out $input_dir/int".$interval."_wis.csv --column 3";

# 		$output_dir = catfile($exp, $ip, '01_split', $algh, "int$interval");
# 		make_path($output_dir, { mode => 0755 }) unless -e $output_dir;

# 		system "utils/split_agregate.pl --file $input_dir/int".$interval.".csv --dir $output_dir --column 8 --acolumn 2";

# 		$output_dir = catfile($exp, $ip, '01_metrics', $algh);
# 		make_path($output_dir, { mode => 0755 }) unless -e $output_dir;
# 		system "utils/metrics.pl --file $input_dir/int".$interval.".csv --out $output_dir/int".$interval.".txt";
# 	}
# }



# $input_dir = catfile($exp, $ip, '02_clustering');
# my @files = glob catfile( $input_dir, '*.csv' );
# my $file;

# $output_dir = catfile($exp, $ip, '02_metrics');
# make_path($output_dir, { mode => 0755 }) unless -e $output_dir;

# for $file ( @files ) {
# 	$file =~ m/^.+\/(.+)\.csv$/;
# 	# say $file;
# 	system "utils/metrics.pl --file $file --out $output_dir/$1.txt";
# 	# last;
# }
