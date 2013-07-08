sub Random_MAC {
    my @values = ();
    push(@values, sprintf("%x0", rand(0xF+1)));

    foreach (2..6) {
        push(@values, sprintf("%02x", rand(0xFF+1)));
    }

    return join(":", @values);
}

sub ShowMACGenerated{
	my $generated_mac = $_[1] || Random_MAC();
	my $value = $_[0]->dialog(
       -message => "Adresse MAC Génerée : $generated_mac - l'utiliser ?",
           -buttons => ['yes', 'no'],
           -title   => 'MAC Gen Module',
    );
	if ($value){
		ApplyMacAddress($generated_mac);
	}
}

sub ShowMACDialog{
	my $macaddress = $_[0]->question("Veuillez entrer l'adresse MAC à utiliser.");
	if ($macaddress) {
		 my $cmac = Net::MAC->new('mac' => $macaddress)->convert(
            'base' => 16,
            'bit_group' => 8,
            'delimiter' => ':'
   		 ); 
		ShowMACGenerated($_[0],$cmac)
	}
}

sub ApplyMacAddress{
	my $mac = $_[0];
	my $iface = GetSelectedInterface();
	Stop_NetworkListener();
	my $tmp = `ifconfig $iface down`;
	sleep(1);
	$tmp = `ifconfig $iface hw ether $mac`;
	$tmp = `ifconfig $iface up`;
	AddLogInfo("MAC Address changed ! Please restart sniffer.\n");
}

sub RestartDHCP{
	my $iface = GetSelectedInterface();
	my $dhcpcmd = `dhclient $iface -r`;
	$dhcpcmd = `dhclient $iface`;
	AddLogInfo("DHCP Renew done !\n");
}
return 1;