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
	$mac = $_[0];
	system("ifconfig wlan0 down");
	sleep(1);
	system("ifconfig wlan0 hw ether $mac");
	system("ifconfig wlan0 up");
}

return 1;