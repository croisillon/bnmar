#!/usr/bin/perl

use strict;
use warnings;
use feature ':5.10';
use File::Spec::Functions qw(catfile);
use Getopt::Long 'HelpMessage';
use FindBin qw($Bin);

my ($file, $outdir, $skip);
GetOptions( 
	'file=s' => \$file,
	'out=s' => \$outdir,
	'skip=i' => \$skip
) or HelpMessage(1);

my ($command, $script, $out, $input, $step_name);
##### ---------- STEP 1 ---------- #####
$step_name = '01 - Filtering';
$script = '01_netflow_filter.pl';
$script = catfile($Bin, $script);
$out = catfile($outdir, 'filtered.txt');
$command = qq{$script --file $file --out $out};
unless ( $skip ) {
	say $step_name;
	say $command;
	$input = $out;
	system $command;
} else {
	say "$step_name has been skipped";
	--$skip;
}


my ($catalog, @agregation, $interval);
##### ---------- STEP 2 ---------- #####
$step_name = '02 - Aggregating';
$script = '02_netflow_agregate.pl';
$script = catfile($Bin, $script);
$catalog = 'agregation';
$file = $input;

unless ( $skip ) {
	say $step_name;
	$catalog = catfile($outdir, $catalog);
	unless ( -e $catalog ) {
		mkdir($catalog) or die $!;
	}

	for $interval ( 2,4,6,8,10,24 ) {
		$out = catfile($catalog, qq{int$interval.csv});
		$command = qq{$script --file $file --interval $interval --out $out};
		say $command;
		system $command;

		push @agregation, [ $interval, $out];
	}
} else {
	say "$step_name has been skipped";
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
	say "$step_name has been skipped";
	--$skip;
}

##### ---------- STEP 4 ---------- #####
my $inter = '/usr/bin/Rscript';
$step_name = "04 - Clustering";
$script = 'run2.r';
$script = catfile($Bin, 'R', $script);
$command = qq{$inter $script $outdir};
say $step_name;
# say $command;
system $command;
