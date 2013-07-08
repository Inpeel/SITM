use HTTP::Daemon;
use HTTP::Status;

my $d = HTTP::Daemon->new || die;
print "Please contact me at: <URL:", $d->url, ">\n";
while (my $c = $d->accept) {
    while (my $r = $c->get_request) {
        $c->send_file_response("Data/sitm.html");
    }
    $c->close;
    undef($c);
}