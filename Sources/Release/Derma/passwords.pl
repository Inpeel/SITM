my $passnum : shared = 1;
my $passbox ;
sub CreatePassDerma{
	my $passwordlist = $_[0]->add(
	    'passwordlist', 'Window',
	    -border => 1,
	    -title => "Logs",
	    -y      => 2,
	    -bfg    => 'red',
	);
	$passbox = $passwordlist->add(
	    'passwordbox', 'Listbox',
	    -values    => ["[".localtime."] - " . "SITM Started."],
	);

}

sub GetPassDermaStatus{
	if($passbox)
	{
		return 1;
	}
	return 0;
}
sub ShowLogDerma{
	$passbox->focus();
}

sub GetLogDerma {
	return $passbox;
}

sub AddLogEntry{
	print STDERR $passbox;
	$passnum++;
	$passbox->insert_at($passnum,$_[0]);
	$passbox->option_last();
	print STDERR $_[0]."\n";
}

sub GoToLast{
	$passbox->option_last();
}

return 1;