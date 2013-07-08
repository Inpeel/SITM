my $router;
my %selectedtargets;
my %hosts;

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
  DrawNotif("$count cible(s) en attente !");
  ShowLogDerma();
}

sub GetAttackTargets{
  return %selectedtargets;
}

sub GetAttackRouter{
  return $router;
}

sub ShowTargets{
  $_[0]->delete('targetlist');
  $_[0]->delete('victimlabel');
  $_[0]->delete('targetbox');
  $_[0]->delete('routerlabel');
  $_[0]->delete('routerbox');
  $_[0]->delete('selectrouterbutton');
  my @Settings = GetSettings();
  my $targetswindow = $_[0]->add(
  	    'targetlist', 'Window',
  	    -border => 1,
  	    -title => "Target List",
  	    -y      => 2,
  	    -bfg    => GetWindowColor(),
  	);
  	

	%hosts = GetResolvedHosts();
  my $router = `route -n | grep ^0.0.0.0 | awk '{print \$2}'`;
  $router =~ s/ //g;
  $router =~ s/\n//g;
  $router =~ s/\r//g;
	my @hostsref;
  foreach my $k (keys(%hosts)) {
    my $hostname = "";
    my $routerstr = "";
     print STDERR "$k IS : $router\r\n";
    if ($k eq $router)
    {

      $routerstr = "[DEFAULT GATEWAY]";
    }
    if (13 ~~ @Settings)
    {
      $hostname = ResolveHostName($k);
    }
    else
    {
      $hostname = "Unresolved";
    }
     push(@hostsref,"IP=$k MAC=$hosts{$k} HOST=$hostname $routerstr\n");
  }

  my $victimlabel = $targetswindow->add(
    'victimlabel', 'Label',
    -text      => 'Select the victims : ',
    -bold       => 1,
    -y       => 1,
  );

  my $targetlistbox = $targetswindow->add(
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
  $targetlistbox->focus();
}
return 1;