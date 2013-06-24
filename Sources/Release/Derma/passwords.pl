my $passnum : shared = 1;
my $passbox ;
sub CreatePassDerma{
	my $passwordlist = $_[0]->add(
	    'passwordlist', 'Window',
	    -border => 1,
	    -title => "Passwords",
	    -y      => 2,
	    -bfg    => GetWindowColor(),
	);
	$passbox = $passwordlist->add(
	    'passwordbox', 'Listbox',
	);

}

sub GetPassDermaStatus{
	if($passbox)
	{
		return 1;
	}
	return 0;
}
sub ShowPassDerma{
	$passbox->focus();
}

sub GetPassDerma {
	return $passbox;
}

sub AddPassEntry{
	print STDERR $passbox;
	$passnum++;
	$passbox->insert_at($passnum,$_[0]);
	$passbox->option_last();
	print STDERR $_[0]."\n";
}

sub GoToLastPass{
	$passbox->option_last();
}

return 1;