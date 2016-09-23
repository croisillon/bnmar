#!/usr/bin/perl

use strict;
use warnings;
use feature ':5.10';
use File::Spec::Functions qw(catfile splitpath);
use Getopt::Long 'HelpMessage';
use FindBin qw($Bin);

my ($file, $outdir, $skip);
GetOptions( 
	'file=s' => \$file,
	'out=s' => \$outdir,
	'skip=i' => \$skip
) or HelpMessage(1);

my @INTERVALS = (2,4,6,8,10);

sub _skipped ($) { say "$_[0] has been skipped"; }

my ($command, $script, $out, $input, $step_name, $inter, $input_dir);
##### ---------- STEP 1 ---------- #####
$step_name = '01 - Filtering';
$script = '01_netflow_filter.pl';
$script = catfile($Bin, $script);
$out = catfile($outdir, 'filtered.txt');
unless ( $skip ) {
	$command = qq{$script --file $file --out $out};
	say $step_name;
	say $command;
	system $command;
} else {
	_skipped $step_name;
	--$skip;
}
$input = $out;


my ($catalog, @agregation, $interval);
##### ---------- STEP 2 ---------- #####
$step_name = '02 - Aggregating';
$script = 'agregate_netflow.pl';
$script = catfile($Bin, $script);
$catalog = 'agregation';
$file = $input;

unless ( $skip ) {
	say $step_name;
	$catalog = catfile($outdir, $catalog);
	unless ( -e $catalog ) {
		mkdir($catalog) or die $!;
	}

	for $interval ( @INTERVALS ) {
		$out = catfile($catalog, qq{int$interval.csv});
		$command = qq{$script --file $file --interval $interval --out $out --verbose};
		say $command;
		system $command;

		push @agregation, [ $interval, $out];
	}
} else {
	_skipped $step_name;
	--$skip;
}

##### ---------- STEP 3 ---------- #####
$step_name = '03 - Binning';
$script = '03_binning.pl';
$script = catfile($Bin, $script);
$catalog = 'binning';

unless ( $skip ) {
	say $step_name;
	$catalog = catfile($outdir, $catalog);
	unless ( -e $catalog ) {
		mkdir($catalog) or die $!;
	}

	while ( $input = shift @agregation ) {
		($interval, $file) = @$input;
		$out = catfile($catalog, qq{int$interval.csv});
		$command = qq{$script --file $file --out $out --interval $interval};
		say $command;
		system $command;
	}
} else {
	_skipped $step_name;
	--$skip;
}

##### ---------- STEP 4 ---------- #####
$inter = '/usr/bin/Rscript';
$step_name = "04 - Clustering step 01";
$script = '01_step.r';
$catalog = 'R';
$script = catfile($Bin, $catalog, $script);

unless ( $skip ) {
	$command = qq{$inter $script $outdir};
	say $step_name;
	system $command;
} else {
	_skipped $step_name;
	--$skip;
}

##### ---------- STEP 5 ---------- #####
$step_name = '05 - Splitting';
$script = 'utils/split_agregate.pl';
$script = catfile($Bin, $script);
$catalog = '01_split';
$input_dir = '01_clustering';

unless ( $skip ) {
	say $step_name;
	$catalog = catfile($outdir, $catalog);
	unless ( -e $catalog ) {
		mkdir($catalog) or die $!;
	}

	for my $interval ( @INTERVALS ) {
		$file = catfile($outdir, $input_dir, qq{int$interval.csv});
		$out = catfile($catalog, qq{int$interval});
		mkdir($out) or die $!;

		$command = qq{$script --file $file --dir $out --column 8 --acolumn 2};
		say $command;
		system $command;
	}
} else {
	_skipped $step_name;
	--$skip;
}

##### ---------- STEP 6 ---------- #####
$inter = '/usr/bin/Rscript';
$step_name = "06 - Clustering step 02";
$script = '02_step.r';
$catalog = 'R';
$script = catfile($Bin, $catalog, $script);

unless ( $skip ) {
	$command = qq{$inter $script $outdir};
	say $step_name;
	system $command;
} else {
	_skipped $step_name;
	--$skip;
}

##### ---------- STEP 8 ---------- #####
$step_name = '08 - Splitting';
$script = 'utils/metrics.pl';
$script = catfile($Bin, $script);
$catalog = '02_metrics';
$input_dir = '02_clustering';

unless ( $skip ) {
	say $step_name;
	$catalog = catfile($outdir, $catalog);
	unless ( -e $catalog ) {
		mkdir($catalog) or die $!;
	}

	my @files = glob(catfile($outdir, $input_dir, 'int*.csv'));
	my $common = catfile($catalog, 'metric.csv');
	unlink($common) if -e $common;

	for my $file ( @files ) {
		$out = catfile($catalog, [splitpath($file)]->[-1]);
		$command = qq{$script --file $file --out $out --column 8 --pattern 195.54.14.121:1731 --common $common};
		say $command;
		system $command;
	}
} else {
	_skipped $step_name;
	--$skip;
}

say 'Done!';
