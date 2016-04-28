#!/usr/bin/perl

use strict;
use warnings;
use feature ':5.10';
use File::Spec::Functions qw(catfile);
use FindBin qw($Bin);

my ($command, $script, $file, $out);

say "02 - Agregate";
$script = '02_netflow_agregate.pl';
$script = catfile($Bin, $script);
$file = $ARGV[0];
$out = catfile($Bin, 'result_agregate.csv');
$command = "$script --file $file --interval 4 --out $out --clean";
system $command;

say "03 - Binning";
$script = '03_binning.pl';
$script = catfile($Bin, $script);
$file = $out;
$out = catfile($Bin, 'result_binning.csv');
$command = "$script --file $file --out $out";
system $command;


