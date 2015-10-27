# findDnsAttacker

This script first written to parse and make some pattern matchings on BIND failure logs. This is a very premature way to ease PRSD attacks especially if you are running BIND.

Currently it listens your incoming interface for DNS traffic ( that you can configure within the script ) and tries to block PRSD domains via iptables.

# How to run ?

In order to run `findDnsAttacker` first of all you need to copy all 3 files into your server.

* findDnsAttacker
* ignoreList.list
* whiteList.list

Then you should edit the first few lines in ```findDnsAttacker``` script like below ;

``` perl
our $threshold = 50;                              # This is the WARNING threshold 
my $blockThreshold = 100;                         # This is the THRESHOLD where a domain get blocked
my $exitThreshold = 10;
my $maxTimeRunning = 120;                         # Run for 120 seconds then exit. 
my $chunkSize = 1000;                             # Check DNS traffic per 1000 queries
our $keepTopInArray = 10;                         # This is for pattern matching algorithm. Recommended not to change :)
my $minBlockLetter = 3;                           # Do not block anything less than 3 letters. 
my $interface = "eth0";                           # My incoming interface
my $filter = "src _LOCALIP_ and dst port 53";     # My filter. Recommended not to change :)
my $daemonLog = "/var/log/daemon.log";            # Not used on this version.
my $version = "0.1.4";              
our $defaultLogLevel = "DEBUG";                   # I want to see many stuff :)
our $logFilename = "/var/log/findAttacker.log";   # Keep logs on this file
our @emailList = ( "" );                          # Sent an email to this addresses, if I block anything
our $SMTPServer = "85.29.60.242";                 # Sent that email via this SMTP server. You should have relay on this server.
```

Then just run it :)

# What does it do ?

Script listens the traffic for PRSD attack. Use pattern matching algorithms to identify if a FQDN is valid or PRSD. It is working on an ISP with high DNS traffic every day, even there are some false positives ( which you should add those to ``whiteList.list``` ) it blockes nearly %95 of PRSD attacks instantaneously.

# What is a PRSD attack ?

It is Pseudo-Random Subdomain Attacks. Some call it "Death by 1000 paper cuts", it really is. A malicious attacker generates DNS traffic against your DNS Server with ;

* Random Source IPs (even we block DNS traffic from out of the country, we have this attack 24/7)
* Random generated Prefix or Suffix subdomains

So usually you have a DNS traffic with a huge amount of Queries like ;
```
aefaeaeuobauerbluaber.9888hh.com
1f3123lg12l3ug123lug1.9888hh.com
9888hh.com.1237g723g17g1237178g7
```

This script filters out ```988hh.com``` from the example above and blockes this string in IP Tables on your incoming traffic, which stops the attack.

# Conclusion

This is not a concrete way to fix this kind of a problem. The attack will evolve and most probably this kind of a method will be obsolete in few years.

There are some specialized DNS companies to have this kind of a functionality within their DNS application code in the market. This is just a free way to handle this kind of an attack with one way :)

Let me know if you have any problems.

