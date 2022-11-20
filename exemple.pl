#!/usr/bin/perl
use strict;
use warnings;

use DKIM;
my $dkim = DKIM->new('domain.com', '/dkim.key');
$dkim->send('test@exemple.cm', 'Subject', 'Message');