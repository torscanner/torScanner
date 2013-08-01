#!/usr/bin/perl
use warnings;

open ASD, "<pre-ports.conf";

while (my $line = <ASD>)
{
if ($line =~ m/(([0-9]*)\/tcp)/ig)
{
	$asd=$1;
	if ($asd =~ m/(\d+)/ig){
		print $1;
		print "\n";
		#	print $asd;
	}

}
}
