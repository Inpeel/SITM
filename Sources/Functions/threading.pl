#!/usr/local/roadm/bin/perl
 
use strict;
use warnings;
use threads;
use threads::shared;
 
print "Start threading...\n";
my $t = threads->new(\&sub1,my $count);
my $t2 = threads->new(\&sub2,my $count2);
$t->join;
$t2->join;
print "Threadings number join !\n";

	sub sub1
		 {
			 for ( my $count = 0; $count <= 101; $count++)
	         	 {
        			print "Started thread n°1 $count fois \n";
				sleep 1;
			 }
		}
	sub sub2
		{
			for (my $count2 = 0; $count2 <=101; $count2++)
			{ 
				print "Started  thread n°2 $count2 fois \n";
				sleep 1;
			}
		}
print "End of program.\n";