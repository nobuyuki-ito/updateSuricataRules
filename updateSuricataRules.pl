#!/usr/bin/perl
use File::Basename 'basename';

my $debug = 1;
my $disabledRuleFilesList = shift;
my $udpOnlyRulesFilesList = shift;
my $disabledProtocolsList = shift;
my $blacklist = shift;
my $ruleFile = shift;
my $destDir = shift;

sub getList {
	my $file = shift;
	my $list = shift;;
	if (-f $file) {
		open LIST, "<", $file or die $!;
		while (my $entry = <LIST>) {
			chomp $entry;
			$entry =~ /^(#|\s*$)/ or push @$list, $entry;
		}
		close LIST;
	}
}

# disable some rules
my @disabledRuleFiles;
getList($disabledRuleFilesList, \@disabledRuleFiles);
my $ruleFileName = basename $ruleFile;
foreach (@disabledRuleFiles) {
	if ($_ eq $ruleFileName) {
		$debug and print STDERR "$0: DEBUG: $_ is disabled; exit\n";
		exit 0;
	}
}

open SRC, "<", $ruleFile or die $!;
open DST, ">", "$destDir/$ruleFileName" or die $!;
my @udpOnlyRuleFiles;
getList($udpOnlyRulesFilesList, \@udpOnlyRuleFiles);
my $udpOnly = 0;
foreach (@udpOnlyRuleFiles) {
	if ($_ eq $ruleFileName) {
		$debug and print STDERR "$0: DEBUG: $ruleFileName: udp only\n";
		$udpOnly = 1;
		last;
	}
}
my @protocols;
getList($disabledProtocolsList, \@protocols);
my @sids;
getList($blacklist, \@sids);

while (my $line = <SRC>) {
# diable tcp rules and enable only udp ones
	if ($udpOnly) {
		$line =~ /^#\s*alert\s+udp/ and $line =~ s/^#\s*//;
		$line =~ /^alert\s+tcp/ and $line =~ s/^/# /;
	} else {
		$line =~ /^#\s*alert\s\S+\s+.+\s+->\s+/ and $line =~ s/^#\s*//;
	}
# remove 'replace' keyword
	$line =~ s/\s*replace:.+?;//;
	my $exclude = 0;
	my $excludeReason;
	my $sid;
# disable some protocols
	if (scalar @protocols) {
		foreach (@protocols) {
			if ($line =~ /^alert\s+$_\s+/) {
				$excludeReason = 'protocol';
				$exclude = 1;
				$line =~ /^alert\s+.+;\s*sid:(\d+)/ and $sid = $1;
				last;
			}
		}
	}
# disable blacklisted rules by sid
	if (scalar @sids) {
		if ($line =~ /^alert\s+.+;\s*sid:(\d+)/) {
			$sid = $1;
			foreach (@sids) {
				if ($sid eq $_) {
					$excludeReason = 'sid';
					$exclude = 1;
					last;
				}
			}
		}
	}
	if ($exclude) {
		$debug and print STDERR "$0: DEBUG: $ruleFileName: sid $sid is disabled by $excludeReason\n";
		$line =~ s/^/# /;
	}
	print DST $line;
}
close SRC;
close DST;

exit 0;
