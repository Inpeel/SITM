my $lognum : shared = 1;
my $listbox ;
sub CreateLogDerma{
	my $packetlist = $_[0]->add(
	    'packetlist', 'Window',
	    -border => 1,
	    -title => "Logs",
	    -y      => 2,
	    -bfg    => GetWindowColor(),
	);
	$listbox = $packetlist->add(
	    'logbox', 'Listbox',
	    -values    => ["[".localtime."] - " . "SITM Started."],
	);

}

sub ShowLogDerma{
	$listbox->focus();
}

sub GetLogDerma {
	return $listbox;
}

sub AddLogEntry{
	print STDERR $listbox;
	$lognum++;
	$listbox->insert_at($lognum,$_[0]);
	$listbox->option_last();
	print STDERR $_[0]."\n";
}

sub GoToLast{
	$listbox->option_last();
}

return 1;