sub Init_Bindings{
	$_[0]->set_binding( sub {DrawNotif("Sniffing demarré !");}, "\cS" );
	$_[0]->set_binding( sub { $menu->focus() }, "\cX" );
	$_[0]->set_binding( \&exit_dialog, "\cQ" );
}

return 1;