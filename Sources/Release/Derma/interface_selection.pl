my $selected_interface;
my $interfaceselection;
sub ButtonCallback($;)
{
   my $this = shift;
   if ($this->get == 1)
   {
   		Start_NetworkListener($selected_interface);
      #GetSelectedInterfaceNetwork($selected_interface);
   		GetLogDerma()->focus();
   		DrawNotif("Sniffing demarré !");
   }
   else
   {
   		GetLogDerma()->focus();
   }
}

sub GetSelectedInterface{
	return $selected_interface;
}

sub GetSelectedInterfaceNetwork{
  my $interface = $selected_interface || $_[0];
  my ($address, $netmask, $err);
  Net::Pcap::lookupnet($interface,\$address,\$netmask,\$err);
  my $ip = inet_ntoa( pack 'N', $address);
  my $mask = inet_ntoa( pack 'N', $netmask);
  if ($err){ print STDERR $err."\n"; }
  print STDERR "Returning...\n";
  my $block = new Net::Netmask($ip,$mask);
  return ($block->first(), $block->last(), $block->size());
}

sub InterfacePopup{
	my @devs = pcap_findalldevs(\%devinfo, \$err);
	$selected_interface = $devs[0];
  if (!$interfaceselection)
  {
  	my $interfacewindow = $_[0]->add(
  	    'interfacelist', 'Window',
  	    -border => 1,
  	    -title => "Selection de l'interface",
  	    -y      => 2,
  	    -bfg    => 'red',
  	);

  	my $infolabel = $interfacewindow->add(
          'InfoLabel', 'Label',
          -text      => 'Veuillez selectionner votre interface pour l\'écoute des paquets.',
          -y		   => 1,
          -bold      => 1,
      );

  	my $interfacelabel = $interfacewindow->add(
          'InterfaceLabel', 'Label',
          -text      => 'Interface : ',
          -y		   => 3,
      );

  	  $interfaceselection = $interfacewindow->add(
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

      my $validatebutton = $interfacewindow->add(
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
  }

	$interfaceselection->focus();
	my $value = $interfaceselection->get();	
}

return 1;