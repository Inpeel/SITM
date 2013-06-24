my $passnum : shared = 1;
my $sessionbox ;
sub CreateSessionDerma{
	my $sessionlist = $_[0]->add(
	    'sessionlist', 'Window',
	    -border => 1,
	    -title => "Sessions",
	    -y      => 2,
	    -bfg    => GetWindowColor(),
	);
	$sessionbox = $sessionlist->add(
	    'sessionbox', 'Listbox',
	    -onchange => \&SessionSelected,
	);

}

sub GetSessionDermaStatus{
	if($sessionbox)
	{
		return 1;
	}
	return 0;
}

sub ShowSessionDerma{
	my %sessions = GetSessions();
	my @keys = keys(%sessions);
	$sessionbox->values(\@keys);
	$sessionbox->labels(\@keys);
	$sessionbox->focus();
}

sub GetSessionDerma {
	return $sessionbox;
}

sub SessionSelected {
	my $listbox = shift;
	my %sessions = GetSessions();
    my ($url) = $listbox->get();
    if (length($url) > 1)
    {
    	 my $mech = WWW::Mechanize::Firefox->new();
         $mech->autoclose_tab( 0 );
         $mech->delete_header('Cookie');
         $mech->add_header(Cookie => $sessions{$url});
         $mech->get($url);
         $mech->add_header(Cookie => $sessions{$url});
    }
   
}

return 1;