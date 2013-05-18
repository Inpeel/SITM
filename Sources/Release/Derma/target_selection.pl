sub ShowTargets{
	my $targetswindow = $_[0]->add(
  	    'targetlist', 'Window',
  	    -border => 1,
  	    -title => "Target List",
  	    -y      => 2,
  	    -bfg    => 'red',
  	);
  	

	my %hosts = GetResolvedHosts();
	my @hostsref;
    foreach my $k (keys(%hosts)) {
       push(@hostsref,"IP=$k MAC=$hosts{$k}\n");
    }

        my $victimlabel = $targetswindow->add(
          'victimlabel', 'Label',
          -text      => 'Select the victims : ',
          -y       => 1,
      );

    my $targetlistbox = $targetswindow->add(
	    'targetbox', 'Listbox',
	    -values    => \@hostsref,
      -y      => 3,
      -multi  => 1,
	);
    $targetlistbox->focus();
}
return 1;