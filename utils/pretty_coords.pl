#!/usr/bin/perl -w

use strict;
use warnings;
use feature ':5.10';
use File::Spec::Functions qw(catfile);

$| = 1;

my $exp = '07';
my $ip = 249;

my @dirs;
push @dirs, catfile($exp, $ip, '01_clustering', 'xmeans', 'coords');
push @dirs, catfile($exp, $ip, '02_clustering', 'coords');

my (@files, $dir, $file, $data, $fh, @lines, @new_lines);
for $dir ( @dirs ) {

	@files = glob catfile( $dir, '*.txt' );
	for $file ( @files ) {
		undef @new_lines;

		open $fh, '<', $file or die $!;
		{
			local $/ = undef;
			$data = <$fh>;
		}
		close $fh;

		$data =~ s/(\\n)/\n/mg;

		@lines = split /\n/, $data;
		for ( my $i = 16; $i < @lines - 4; ++$i ) {

			next unless ( $lines[$i] =~ m/Cluster \d+/);
			# say $lines[$i];
			$lines[$i] =~ s/\+$//;
			$lines[$i+1] =~ s/^\s+//;
			$lines[$i+1] =~ s/\s/;/g;

			push @new_lines, sprintf("\"%s\";%s\n", $lines[$i], $lines[$i+1]);
			++$i;
		}

		$data = join '', @new_lines;
		
		if (length $data) {
			open $fh, '>', $file or die $!;
			print $fh $data;
			close $fh;
		}
	}
	
}
