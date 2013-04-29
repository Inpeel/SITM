#! /usr/bin/perl -w

use Net::ARP;

$| = 1;
my $mac = Net::ARP::arp_lookup("wlan0","10.8.97.1");
print "adresse mac actuelle :".$mac;
my $noblock = 1;
do
{
	$macActuelle = Net::ARP::arp_lookup("wlan0","10.8.97.1");
	if($mac ne $macActuelle and $macActuelle ne "unknown")
	{
		print "alert\n";
		print "vraie adresse".$mac;
		print "\nadresse actuelle".$macActuelle;

		system("notify-send --urgency=CRITICAL 'USURPATION ARP DETECTEE !'");
		$noblock = 0;
			
	}
	print "Scanning...\n";
	sleep(1);
} while ($noblock);

