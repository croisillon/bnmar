#!/usr/bin/perl

use strict;
use warnings;
use feature ':5.10';
use File::Spec::Functions qw(catfile);
use Getopt::Long 'HelpMessage';
use FindBin qw($Bin);

my ($file, $outdir);
GetOptions( 
	'file=s' => \$file,
	'out=s' => \$outdir
) or HelpMessage(1);

my ($command, $script, $out, $input);
##### ---------- STEP 1 ---------- #####
say "01 - Filtering";
$script = '01_netflow_filter.pl';
$script = catfile($Bin, $script);
$out = catfile($outdir, 'filtered.txt');
$command = qq{$script --file $file --out $out};
say $command;
$input = $out;
system $command;


my ($catalog, @agregation, $interval);
##### ---------- STEP 2 ---------- #####
say "02 - Agregate";
$script = '02_netflow_agregate.pl';
$script = catfile($Bin, $script);
$catalog = 'agregation';
$file = $input;

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

##### ---------- STEP 3 ---------- #####
say "03 - Binning";
$script = '03_binning.pl';
$script = catfile($Bin, $script);
$catalog = 'binning';

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

##### ---------- STEP 4 ---------- #####
my $inter = '/usr/bin/Rscript';
say "04 - Clustering";
$script = 'run2.r';
$script = catfile($Bin, 'R', $script);
$command = qq{$inter $script $outdir};
say $command;
system $command;
