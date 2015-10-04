#!/usr/bin/perl
#
#
# findAttacker  -    This scripts gets BIND loging data via STDIN and performs pattern matching
#                    to identify any attacker. 
#
# Author            Emre Erkunt
#                   (emre.erkunt@superonline.net)
#
# History :
# -----------------------------------------------------------------------------------------------
# Version               Editor          Date            Description
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# 0.0.1_AR              EErkunt         20150210        Initial ALPHA Release
# 0.0.1                 EErkunt         20150210        Initial Live Release
# 0.0.2                 EErkunt         20150210        Added logging functionality
#                                                       Added mail notification system via SMTP
#                                                       Ensured that only one copy runs
#                                                       Added time based exit
# 0.0.3                 EErkunt         20150211        Added additional logging
# 0.0.4                 EErkunt         20150211        Smarter blocking/suspcious marking
# 0.0.5                 EErkunt         20150211        Reading daemon log in the script
# 0.0.6                 EErkunt         20150213        Parsing LIVE traffic instead of error log
# 0.1.0                 EErkunt         20150216        Changed the pattern matching algorithm 
#                                                       by linked lists.
# 0.1.1                 EErkunt         20150218        Improved whitelisting algorithm
# 0.1.2                 EErkunt         20150311        Fixed a problem that script blocks empty
#                                                       records.
# 0.1.3                 EErkunt         20150311        Added minimum letter count for block action
# 0.1.4                 EErkunt         20150403        Changed whitelisting algorithm
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#
# Needed Libraries
#
use POSIX;
use Fcntl ':flock';
use Net::SMTP;
use Getopt::Std;
use Data::Dumper;
use Sys::Hostname;
use Socket;

my %opt;
my $arguments   = "q";
getopts( $arguments, \%opt ) or usage();

our $defaultLogLevel = "DEBUG";
our $logFilename = "/var/log/findAttacker.log";
#
# Main Loop
#
# Beware, dragons beneath here! Go away.
#
our %patternData;

my $i = 0;
our $threshold = 50;
my $blockThreshold = 100;
my $exitThreshold = 10;
my $maxTimeRunning = 120;
my $chunkSize = 1000;
our $keepTopInArray = 10;
my $minBlockLetter = 3;
my $interface = "eth0";
my $filter = "src _LOCALIP_ and dst port 53";
my $daemonLog = "/var/log/daemon.log";
my $version = "0.1.4";
our $defaultLogLevel = "DEBUG";
our $logFilename = "/var/log/findAttacker.log";
our @emailList = ( ); # Your emails should be here
my $baseDir = "/etc/findAttacker" # Change this to however you like.
our $SMTPServer = ""; # Your SMTP Server IP should be here.

$| = 1;
our @ignoreList;
our @whiteList;

# 
# Ensures only 1 copy runs at a time
INIT {
        open  LH, $0 or logMe("FATAL", "Can't open $0 for locking!\nError: $!\n");
        flock LH, LOCK_EX|LOCK_NB or die "$0 is already running!\n";
    }
	

open(IGNORELIST, $baseDir."/ignoreList.list") or logMe("FATAL", "Can not find any ignore list ".$baseDir."/ignoreList.list");
while(<IGNORELIST>) {
	chomp($_);
	push(@ignoreList, $_);
}
close(IGNORELIST);

open(WHITELIST, $baseDir."/whiteList.list") or logMe("FATAL", "Can not find any ignore list ".$baseDir."/whiteList.list");
while(<WHITELIST>) {
	chomp($_);
	push(@whiteList, $_);
}
close(WHITELIST);

my $addr =inet_ntoa((gethostbyname(hostname))[4]);
$filter =~ s/_LOCALIP_/$addr/g;

our @blocked;
our $linkedData = {};
my $count = 0;
my $goExit = 0;
my $startedTime = time();
my $percentage = 0;
our $swirlCount = 1;
our $swirlTime  = time();

print "findAttacker v".$version."\n";
print "Detection started on listening outgoing DNS related data for $addr with ".scalar(@ignoreList)." TLD ignores.\n";
print "Suspicious threshold is $threshold, enforcement threshold is $blockThreshold.\n";
logMe("INFO", "findAttacker v".$version." has started with ".scalar(@ignoreList)." TLD ignores.");
# open(DAEMONFILE, "/usr/bin/tail --retry --follow=name $daemonLog |") or logMe("FATAL", "Can not open daemon.log");
open(DAEMONFILE, "/usr/sbin/tcpdump -i $interface -nn \"$filter\" 2>&1 |") or logMe("FATAL", "Can tap interface!");
print " ";
while(<DAEMONFILE>) {
	# Feb 10 09:57:48 cdns-06sgtz-02 named[29521]: error (FORMERR) resolving 'service.supercell.net/AAAA/IN': 205.251.197.147#53
	# if ( $_ =~ /\w+ \d* \d\d:\d\d:\d\d .* named\[\d*\]: error \(.*\) resolving '(.*)\/\w*\/IN': (.*)#53/ ) {
	
	# 10:39:24.699156 IP 212.252.133.52.55789 > 213.74.1.1.53: 40371+ A? llcccqozo.www.9888hh.com. (42)
	# 15:20:58.478522 IP 82.222.179.62.8861 > 182.140.167.188.53: 9576 [1au] A? kjkbsngjmpahwxmz.vip.jingzi.cc. (59)
	
	if ( $_ =~ /\d*:\d*:\d*\.\d* IP \d*\.\d*\.\d*\.\d*\.\d* > \d*\.\d*\.\d*\.\d*\.\d*: \d*[\s%\[\]A?1auSRVPTOXMNYervFailtype1895CNEzoneIb2&3=0x]+ (.*)\. \(\d*\)/ ) {
		# findPattern($1);
		findLinkedPattern($1);
		$i++;
		
		if ( $i%100 eq 0 ) {
			&swirl();
			if ( ( time()-$startedTime > $maxTimeRunning ) and $goExit eq 0 ) {
				$goExit = 1;
				logMe("INFO", "Exceed running time limit ( $maxTimeRunning ), exiting.");
			}
		}
		
		# Block Domains
		if ( $i%$chunkSize eq 0 ) {
			$percentage += sprintf("%d", (100/$exitThreshold));
			my %patterns = findMostLinkedOne();
			foreach my $suspiciousPattern ( keys %patterns ) {
				if ( length($suspiciousPattern) ) {
					if ( length($suspiciousPattern) > $minBlockLetter ) {
						if ( $patterns{$suspiciousPattern} > $blockThreshold ) {
							if ( !in_array(\@blocked, $suspiciousPattern) ) {
									print "\b==! BLOCKED pattern : $suspiciousPattern ( $patterns{$suspiciousPattern}/$blockThreshold match count )\n ";
									push(@blocked, $suspiciousPattern);
									system("/sbin/iptables -A INPUT -i eth0 -p udp -m udp --dport 53 -m string --string \"".$suspiciousPattern."\" --algo bm --from 20 --to 100 -j DROP");
									logMe("INFO", "Pattern $pattern has been blocked !");
							}
						} elsif ( $patterns{$suspiciousPattern} > $threshold ) {
							print "\b==> Found suspicious pattern : $suspiciousPattern ( Hit ".sprintf("%.1f", ($patterns{$suspiciousPattern}/$threshold) * 100)."% suspcious ratio, ".sprintf("%.1f", ($patterns{$suspiciousPattern}/$blockThreshold) * 100)."% blocked ratio with $patterns{$suspiciousPattern} match count )\n ";
						}
					}
				}
			}
			
			$count++;
			if ( $count >= $exitThreshold or $goExit ) {
				print "\bOperation completed with ".scalar(@blocked)." blocked patterns.\n";
				logMe("INFO", "Operation completed with ".scalar(@blocked)." blocked patterns in $i total FQDNs."); 
				if ( scalar(@blocked) ) {
					notifyViaEmail()
				}
				close(DAEMONFILE);
				exit;
			}
		}
	}
}
close(DAEMONFILE);


# 
# Relation functions
#
sub findPattern( $ ) {
	my $FQDN = shift;
	
	# print "-?> $FQDN\n";
	my @octets = split(/\./, $FQDN);
	foreach my $octet ( @octets ) {
		if ( !in_array(\@ignoreList, $octet) ) {
			if ( !in_array(\@blocked, $octet) ) {
				if ( $patternData{$octet} ) {
					$patternData{$octet}++;
				} else {
					$patternData{$octet} = 1;
				}
				# print "--> $octet = $patternData{$octet}\n";
			} else {
				print "$octet is already blocked.\n";
			}
		}
	}
}

sub findLinkedPattern( $ ) {
	my $FQDN = shift;
	
	# print "<-- $FQDN -->\n";
	my @octets = split(/\./, $FQDN);
	my $whiteListed = 0;
	
	foreach my $whiteList ( @whiteList ) {
		#
		# Check for whitelisting
		if ($FQDN =~ /.*$whiteList.*/ ) {
			# print "WHITELISTED: $whiteList in $FQDN\n";
			return;
		}
	}
	# print "FILTERING : $FQDN\n";
		
	#
	# Re-structure Array
	my @tmpOctets;
	for ( my $i = (scalar(@octets)-1); $i>=0; $i-- ) {
		if ( !in_array(\@ignoreList, $octets[$i]) ) {
			if ( !in_array(\@blocked, $octets[$i]) ) {	
				push(@tmpOctets, $octets[$i]);
			} else {
				# print "[$i] Already blocked $octets[$i]\n";
			}
		} else {
			# print "[$i] Ignored $octets[$i]\n";
		}
		if ($octets[$i] =~ /^\d*$/) {
			# print "[$i] Ignored number $octets[$i]\n";
		} elsif ($octets[$i] =~ /\?/) {
			# print "[$i] Ignored invalid FQDN octet $octets[$i]\n";
		}
	}
	if ( $whiteListed > 0 ) {
		# print "** FQDN $FQDN is whitelisted!\n";
		undef @octets;
	} else {
		# print "** Array reduced to ".scalar(@tmpOctets)." from ".scalar(@octets).". New FQDN is ".join(".", @tmpOctets)."\n";
		@octets = @tmpOctets;
	}
	
	#
	# First establish connections
	for ( my $i = 0; $i < (scalar(@octets)); $i++ ) {
		if ( $i == 0 ) {
			#
			# I am gROOT!
			# print "[$i] Processing $octets[$i] ( ROOT )\n";
			if ( $linkedData->{"ROOT"}->{$octets[$i]} ) {
				# print "-> [$i] Pattern $octets[$i] already exist.\n";
				$linkedData->{"ROOT"}->{$octets[$i]}++;
			} else {
				# print "-> [$i] Creating pattern $octets[$i].\n";
				$linkedData->{"ROOT"}->{$octets[$i]} = 1;
			}
		} else {
			#
			# Links some connections to the root
			# print "-> [$i] Linking ".$octets[$i]." -> ".$octets[$i-1]."\n";
			if ( $linkedData->{$octets[$i-1]}->{$octets[$i]} ) {
				$linkedData->{$octets[$i-1]}->{$octets[$i]}++;
			} else {
				$linkedData->{$octets[$i-1]}->{$octets[$i]} = 1;
			}
		}
	}
	
	# print Data::Dumper->Dump([\$linkedData]);
	# print "</- $FQDN -/>\n\n";
}

sub findMostLinkedOne {
	# print "*************** FINDING THE MOST LINKED ONE\n";
	#print Data::Dumper->Dump([\$linkedData]);
	my %linkCount;
	my $output;
	foreach my $octet ( keys %{$linkedData->{"ROOT"}} ) {
		$output = $octet." : " if ( $opt{q} );
		my @childs = keys(%{$linkedData->{$octet}});
		my %visited = ();
		$linkCount{$octet} = 1;
		my $childCount = 0;
		foreach my $subOctet ( @childs ) {
			next if exists $visited{$subOctet};
			$output .= "[$subOctet] " if ( $opt{q} );
			if ( $linkedData->{$subOctet} ) { push(@childs, $subOctet); }
			$visited{$subOctet} = 1;
			$childCount++;
		}
		$linkCount{$octet} += $childCount;
		$output .= "($linkCount{$octet})\n" if ( $opt{q} );
		if ( $opt{q} and $linkCount{$octet} > $threshold ) {
			print $output;
		}
		# print ".";
	}
	# print "\n";
	
	my $count = 0;
	my %return;
	foreach my $octet ( sort { $linkCount{$b} <=> $linkCount{$a} } keys %linkCount ) {
		# print "$linkCount{$octet} - $octet\n";
		$count++;
		$return{$octet} = $linkCount{$octet};
		if ( $count > $keepTopInArray ) {
			last;
		}
	}	
	
	return %return;
	# print "FINDING THE MOST LINKED ONE ***************\n\n";
}

sub in_array {
     my ($arr,$search_for) = @_;
     my %items = map {$_ => 1} @$arr; 
     return (exists($items{$search_for}))?1:0;
}

sub logMe( $ $ ) {
	my $logLevel = shift;
    my $logMessage = shift;
    my $now = POSIX::strftime("%Y-%d-%m %T", localtime);
    
    my $level = 5;
    my $quit  = 0;
	
	if    ( $logLevel =~ /debug/i ) 	{ $level = 10; }
	elsif ( $logLevel =~ /info/i ) 		{ $level = 5; }
	elsif ( $logLevel =~ /warning/i ) 	{ $level = 1; }
	elsif ( $logLevel =~ /err/i ) 		{ $level = 0; }
	elsif ( $logLevel =~ /fatal/i ) 	{ $level = -1; }
	else 								{ die $logLevel." can not be found in logLevels!!\n"; }
    
    if ( $level >= $defaultLogLevel ) {
        open(LOGFILE, ">> ".$logFilename) or die ("Can not open log file $logFilename for writing!");
        my @lines = split("\n", $logMessage);
        foreach my $msg ( @lines ) {
            chomp($msg);
            if ( $msg ) {
                print LOGFILE "[".$now."] ".$logLevel." ".$msg."\n";
				# print "[".$now."] ".$logLevel." ".$msg."\n";
                print "\n\nFATAL ERROR :" if($level < 0);
                print $msg."\n" if ($level < 0 );
            }
        }
        close(LOGFILE);
        exit if ($level < 0);
    }
}

sub swirl() {
	
	my $diff = 1;
	my $now = time();	
	
	if    ( $swirlCount%8 eq 0 ) 	{ print "\b|"; $swirlCount++; }
	elsif ( $swirlCount%8 eq 1 ) 	{ print "\b/"; $swirlCount++; }
	elsif ( $swirlCount%8 eq 2 ) 	{ print "\b-"; $swirlCount++; }
	elsif ( $swirlCount%8 eq 3 ) 	{ print "\b\\"; $swirlCount++; }
	elsif ( $swirlCount%8 eq 4 ) 	{ print "\b|"; $swirlCount++; }
	elsif ( $swirlCount%8 eq 5 ) 	{ print "\b/"; $swirlCount++; }
	elsif ( $swirlCount%8 eq 6 ) 	{ print "\b-"; $swirlCount++; }
	elsif ( $swirlCount%8 eq 7 ) 	{ print "\b\\"; $swirlCount++; }

	return;
	
}

sub notifyViaEmail() {
	# print "Sending email via $SMTPServer\n";
	my $smtp = 	Net::SMTP->new($SMTPServer, Timeout => 60);
	# print "Sending from : findDNSAttacker\@alarms.superonline.net\n";
	$smtp->mail("findDNSAttacker\@alarms.superonline.net");
	foreach my $to (@emailList) {
		print "=> To: $to\n";
		$smtp->to($to);
	}
	
	$smtp->data();
	# print "==> DATA START <==\n";
	my $data = "From: findDNSAttacker\@alarms.superonline.net\n";
	foreach my $to (@emailList) {
		$data .= "To: ".$to."\n";
	}
	my $hostname = `/bin/hostname`;
	$data .= "Subject: BLOCKED DOMAIN NOTIFICATION on $hostname\n";
	$data .="\n";
	chomp($hostname);
	$data .= "ALARM NOTIFICATION ON $hostname\n\n";
	$data .= "The patterns listed below has been blocked ;\n";
	foreach my $pattern ( @blocked ) {
		$data .= "   * $pattern\n";
	}
	$data .= "\n\n";
	$data .= "Current iptables rules looks like ;\n";
	open(IPTABLES, "/sbin/iptables -L -n -v |") or die("Can not run iptables");
	while(<IPTABLES>) {
		$data .= $_;
	}
	close(IPTABLES);
	# print $data."\n";
	# print "==> DATA END <==\nSending email..";
	$smtp->datasend($data);
	$smtp->dataend();
	$smtp->quit;
	# print "Sent!\n";
	logMe("INFO", "Notification emails sent to ".join(",", @emailList)." addresses.");
}
