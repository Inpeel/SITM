my $status = 0;
sub GetARPWatchStatus {
	return $status;
}

sub CheckARPTable {
	$status = 1;
	$_[0]->status("SITM ARP Watcher is running /!\\");
	Time::HiRes::sleep(0.5);
	$_[0]->status("SITM ARP Watcher is running / \\");
	Time::HiRes::sleep(0.5);
	$_[0]->status("SITM ARP Watcher is running /!\\");
	Time::HiRes::sleep(0.5);
	$_[0]->status("SITM ARP Watcher is running / \\");
	Time::HiRes::sleep(0.5);
	$_[0]->status("SITM ARP Watcher is running /!\\");
	Time::HiRes::sleep(0.5);
	$_[0]->nostatus;
}

return 1;