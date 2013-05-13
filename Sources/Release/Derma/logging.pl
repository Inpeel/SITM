my $lognum = 1;
my $listbox;
sub CreateLogDerma{
	my $packetlist = $_[0]->add(
	    'packetlist', 'Window',
	    -border => 1,
	    -title => "Logs",
	    -y      => 15,
	    -bfg    => 'red',
	);
	$listbox = $packetlist->add(
	    'logbox', 'Listbox',
	    -values    => ["[".localtime."] - " . "SITM Started."],
	);

}

sub AddLogEntry{
	$lognum++;
	$listbox->insert_at($lognum,"[".localtime."] - " .$_[0]);
	print STDERR $_[0]."\n";
}

return 1;