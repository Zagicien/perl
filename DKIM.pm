package DKIM;
use strict;
use Encode qw( encode_utf8 );

use MIME::Base64;
use Digest::SHA qw(sha256);
use Crypt::OpenSSL::RSA;

sub new {
	my $class = shift;
	my $self = {};
	$self->{DKIM} = {};
	$self->{DKIM}->{d} = shift;
	my $filename = shift;
	open my $fh, '<', $filename or die "error opening $filename: $!";
	my $s = do { local $/; <$fh> };
	$s =~ s/^\s+|\s+$//g;
	$self->{rsa_priv} = new_private_key Crypt::OpenSSL::RSA( $s );
	$self->{rsa_priv}->use_sha256_hash;
	my @DK = ('v', 'a', 'q', 's', 't', 'c', 'h', 'd', 'bh', 'b');
	$self->{DK} = \@DK; 
	$self->{DKIM}->{v} = '1';
	$self->{DKIM}->{a} = 'rsa-sha256';
	$self->{DKIM}->{q} = 'dns/txt';
	$self->{DKIM}->{s} = 'dkim';
	$self->{DKIM}->{c} = 'relaxed/relaxed';
	$self->{DKIM}->{h} = 'mime-version:from:to:subject';
	$self->{DKIM}->{b} = '';
	return bless $self, $class;
}

sub sign {
	my $self = shift;
	my $to = shift;
	my $subject = shift;
	my $body = shift;
	$self->{DKIM}->{t} = time();
	$body=~s/\n/\r\n/g;
	$body=~s/\r\n\n/\r\n/g;
	$self->{DKIM}->{bh} = encode_base64(sha256($body . "\r\n"), '');
	$self->{DKIM}->{bh} =~ tr/\015\012 \t//d;
	my $head = "mime-version:1.0\r\nfrom:\"".$self->{DKIM}->{d}."\" <root@".$self->{DKIM}->{d}.">\r\nto:".$to."\r\nsubject:".$subject."\r\n";
	my $dkim1 = $head . $self->build('dkim-signature:', ' ', -2);
	my $dkim2 = $self->build('DKIM-Signature: ', "\r\n\t", -4);
	my $sign = encode_base64($self->{rsa_priv}->sign($dkim1), '');
	return $dkim2 . $sign . "\r\nMIME-Version: 1.0\r\nFrom: ".$self->{DKIM}->{d}." <root\@".$self->{DKIM}->{d}.">\r\nContent-type: text/html; charset=utf8";
}

sub build {
	my $self = shift;
	my $a = shift;
	my $b = shift;
	my $c = shift;
	for my $key (values @{ $self->{DK} }) {
		$a.="$key=".$self->{DKIM}->{$key}.";$b";
	}
	return substr (encode_utf8($a), 0, $c);
}

sub as_string {
	return shift->{as_string};
}

sub send {
	my $self = shift;
	my $a = shift;
	my $b = shift;
	my $c = shift;
	my $self->{as_string} = "To: $a\nSubject: $b\n". $self->sign($a, $b, $c)."\n\n$c";
	open(MAIL, "|/usr/sbin/sendmail -t");
	print MAIL $self->{as_string};
	return close(MAIL) ? 0 : 1;
}

1;