#!/usr/bin/perl -w
defined($pid = fork) or die "Pas de fork possible : $!";
unless($pid) {
print "Processus fils.\n";
 for ( my $count = 0; $count <= 101; $count++)
	     	 {
				print "Started thread n°1 $count fois \n";
			sleep 1;
		 }
}
print "Retour au père.";
