my $selected_interface = "";

sub ButtonCallback($;)
{
   my $this = shift;
   if ($this->get == 1)
   {
   		Start_NetworkListener($selected_interface);
   		GetLogDerma()->focus();
   		 DrawNotif("Sniffing demarré !");
   }
   else
   {
   		GetLogDerma()->focus();
   }
   print STDERR "DICKZ : " . $this->get . "\n";
}

sub GetSelectedInterface{
	return $selected_interface;
}

sub InterfacePopup{
	my @devs = pcap_findalldevs(\%devinfo, \$err);
	$selected_interface = $devs[0];

	my $win = $_[0]->add(
	    'interfacelist', 'Window',
	    -border => 1,
	    -title => "Selection de l'interface",
	    -y      => 2,
	    -bfg    => 'red',
	);

	my $infolabel = $win->add(
        'InfoLabel', 'Label',
        -text      => 'Veuillez selectionner votre interface pour l\'écoute des paquets.',
        -y		   => 1,
        -bold      => 1,
    );

	my $interfacelabel = $win->add(
        'InterfaceLabel', 'Label',
        -text      => 'Interface : ',
        -y		   => 3,
    );

	my $interfaceselection = $win->add(
	    'interfaceselection', 'Popupmenu',
	    -x 		   => 12,
	    -y		   => 3,
	    -values    => \@devs,
	    -onchange  => sub {
	    	my $pm = shift;
			my $lbl = $pm->parent->getobj('interfaceselection');
			$selected_interface = $pm->get;
	    }
	);

    my $validatebutton = $win->add(
        'validatebutton', 'Buttonbox',
        -y		   => 5,
        
        -buttons   => [
            { 
              -label => 'Valider',
              -value => 1,
              -onpress => \&ButtonCallback, 
              -shortcut => 1 
            },{ 
              -label => 'Annuler',
              -value => 2,
              -onpress => \&ButtonCallback, 
              -shortcut => 2 
            }
        ]
    );

	$interfaceselection->focus();
	my $value = $interfaceselection->get();	
}

return 1;