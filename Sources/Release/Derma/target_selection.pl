my $router;
my %selectedtargets;
my %hosts;
my $targetlistbox;

sub victimbox_callback()
{
    my $listbox = shift;
    
    my @sel = $listbox->get;
    %selectedtargets = ();
    foreach my $target (@sel)
    {
      my ($ip) = $target =~ m/IP=(.*?) MAC/;
      $selectedtargets{$ip} = $hosts{$ip};
    }
    
}

sub ButtonClickCallback{
  DrawNotif("TARGETS SET !");
}

sub routerbox_callback{
  my $listbox = shift;
  ($router) = $listbox->get =~ m/IP=(.*?) MAC/;
}

sub ShowVictimsCallback{
  foreach my $k (keys(%selectedtargets)) {
     print STDERR "ARP SPOOFING SIP=$k SMAC=$hosts{$k} USING IP : $router\n";
  }
  my $count = scalar(keys %selectedtargets);
  DrawNotif("$count cibles en attentes !");
  ShowLogDerma();
}

sub GetAttackTargets{
  return %selectedtargets;
}

sub GetAttackRouter{
  return $router;
}

sub ShowTargets{
	if (!$targetlistbox)
  {
    my $targetswindow = $_[0]->add(
    	    'targetlist', 'Window',
    	    -border => 1,
    	    -title => "Target List",
    	    -y      => 2,
    	    -bfg    => GetWindowColor(),
    	);
    	

  	%hosts = GetResolvedHosts();
  	my @hostsref;
    foreach my $k (keys(%hosts)) {
      my $hostname = ResolveHostName($k);
       push(@hostsref,"IP=$k MAC=$hosts{$k} HOST=$hostname\n");
    }

    my $victimlabel = $targetswindow->add(
      'victimlabel', 'Label',
      -text      => 'Select the victims : ',
      -bold       => 1,
      -y       => 1,
    );

    $targetlistbox = $targetswindow->add(
      'targetbox', 'Listbox',
      -values    => \@hostsref,
      -y      => 3,
      -vscrollbar => 1,
      -height      => 5,
      -multi  => 1,
      -onchange   => \&victimbox_callback,
  	);

    my $routerlabel = $targetswindow->add(
      'routerlabel', 'Label',
      -text      => 'Select the router : ',
       -bold       => 1,
      -y       => 9,
    );

     my $routerlistbox = $targetswindow->add(
      'routerbox', 'Listbox',
      -values    => \@hostsref,
      -y      => 11,
      -vscrollbar => 1,
      -height      => 5,
      -onchange => \&routerbox_callback,
    );

    my $selectrouterbutton = $targetswindow->add(
        'selectrouterbutton', 'Buttonbox',
        -y       => 17,
        
        -buttons   => [
            { 
              -label => 'Valider',
              -value => 1,
              -onpress => \&ShowVictimsCallback, 
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
  $targetlistbox->focus();
}
return 1;