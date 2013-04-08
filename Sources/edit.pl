#!/usr/bin/perl -w

use strict;
use Curses::UI;
my $cui = new Curses::UI( -color_support => 1 );

# Create a menu
my @menu = (
	{
		-label   => 'SITM 1.0',
		-submenu => [ { -label => 'Test', -value => \&PrintSomeShit }]
	},
	{
		-label   => 'File',
		-submenu => [ { -label => 'Exit      ^Q', -value => \&exit_dialog } ]
	},
);

# Dialogs
sub exit_dialog() {
	my $return = $cui->dialog(
		-message => "Do you really want to quit?",
		-title   => "Are you sure???",
		-buttons => [ 'yes', 'no' ],

	);

	exit(0) if $return;
}

sub PrintSomeShit(){
	print("HELLO WORLD !");
}

# Add the Menubar
my $menu = $cui->add(
	'menu', 'Menubar',
	-menu => \@menu,
	-fg   => "blue",
);

# Add a window
my $win1 = $cui->add(
	'win1', 'Window',
	-border => 1,
	-y      => 1,
	-bfg    => 'red',
);

# Add a widget 
my $texteditor = $win1->add( "text", "TextEditor",
	-text => "Here is some text\n" . "And some more" );

# Making keybindings
$cui->set_binding( sub { $menu->focus() }, "\cX" );
$cui->set_binding( \&exit_dialog, "\cQ" );

# The final steps
$texteditor->focus();
$cui->mainloop();
