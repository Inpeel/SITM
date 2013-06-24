my $status = 0;
sub GetARPWatchStatus {
	return $status;
}

sub CheckARPTable {
	$status = 1;
	AddLogEntry("SITM ARP Watcher started.");
	defined($pid = fork) or die "Pas de fork possible : $!";
	unless($pid) {
		my $router_ip = "10.8.97.1";
		my $original_router_mac = Net::ARP::arp_lookup("p5p1","10.8.97.1");
		my $noblock = 1;
		$_[0]->status("SITM ARP Watcher is running /!\\");
		Time::HiRes::sleep(0.5);
		$_[0]->status("SITM ARP Watcher is running / \\");
		Time::HiRes::sleep(0.5);
		$_[0]->status("SITM ARP Watcher is running /!\\");
		Time::HiRes::sleep(0.5);
		$_[0]->nostatus;
		do
		{
			$router_mac = Net::ARP::arp_lookup("p5p1",$router_ip);
			if($original_router_mac ne $router_mac and $router_mac ne "unknown")
			{
				my $arpalertdialog = $_[0]->dialog(
			       -message => "Modification de la table ARP !\nOriginal : $original_router_mac - Modifiée : $router_mac\n\nRedefinir l'adresse MAC ?",
			           -buttons => ['yes', 'no'],
			           -title   => 'SITM ARP Watcher',
			    );
			    if ($arpalertdialog){
			    	system("arp -s $router_ip $router_mac > /dev/null");
			    }
				$noblock = 0;
				
			}
			sleep(1);
		} while ($noblock);
	}

}

return 1;