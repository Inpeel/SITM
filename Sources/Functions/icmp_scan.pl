use Net::Ping;
$p = Net::Ping->new();
print "$host is alive.\n" if $p->ping($host);
$p->close();
