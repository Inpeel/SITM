#!/usr/bin/perl

use strict;
use DBI;

my $dbh = DBI->connect(
    "dbi:SQLite:dbname=cookies.sqlite",
    "",
    "",
    { RaiseError => 1 },
) or die $DBI::errstr;


$dbh->do("SELECT * FROM moz_cookies");
#$dbh->do("CREATE TABLE Cookies(Id INT PRIMARY KEY, Name TEXT, Price INT)");
#$dbh->do("INSERT INTO Cookies VALUES(1,'Audi',52642)");

my $sth = $dbh->prepare("INSERT INTO moz_cookies(name,baseDomain,value,host, path, expiry, isSecure, isHttpOnly, lastAccessed) VALUES
(' miam_key ',
' facebook.us',
' sdsdkdJFHEO48787',
' facebook.us ',
' / ',
' 2219236910',
' 84600',
' 0',
' 1216818073366141')
");
$sth->execute();

my $sth = $dbh->prepare("SELECT * FROM moz_cookies");
$sth->execute();

  my $emps = $dbh->selectall_arrayref(
      "SELECT * FROM moz_cookies;",
      { Slice => {} }
  );
  foreach my $emp ( @$emps ) {
      print "COOKIEEE: $emp->{host}\n";
  }
$sth->finish();
$dbh->disconnect();


