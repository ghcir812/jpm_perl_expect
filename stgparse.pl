#!/usr/bin/perl -w
#use warnings;
#use strict;
use Expect;
use IO::File;

#
# usage stgparse.pl <ssid> <hba pwwn>
#

my $debug = 1;

my $SYMM_INFO_FILE = "/home/symm_info_file";

### globally disable output of commands
$Expect::Log_Stdout = 0;

#for just a command, to disable output:
# $exp->log_stdout(0);


### how long to expect - undef - forever ###
my $timeout = 8;
my $savedtimeout = $timeout;

my $level = 0;
my $password = "xxxxxxxx";
my $rpassword = "xxxxxxxx";
my $prompt = "#|>";
my $ssid;
my $swtype;
my $sw_vendor;


### Auto Flush
###
$|=1;


### Log Output file...
###

$outfile = "stg_output_$$.log";
$tee = "| tee -a $outfile";

$ssid = shift @ARGV;
$hba_pwwn = shift @ARGV;
my $emcpwwn = remove_colons($hba_pwwn);
printf("HBA PWWN = %s\n", $emcpwwn);


###
### Subroutines
###

sub remove_colons {
   my $pwwn = $_[0];

   $pwwn =~ s/://g;
   return $pwwn;
}


sub setsym {
   my $ssid = $_[0];
   my $site;

   if ($debug) {
      printf("...enter setsym\n");
   }

   printf("looking for ssid = %s\n", $ssid);
   open(INFO, $SYMM_INFO_FILE) || die "could not open $SYMM_INFO_FILE\n";

   while(<INFO>) {
      if (/^([A-Z0-9_]+)\W.*($ssid).*/) {
         $site = $1;
         printf("site is set to %s\n", $site);
#         $ENV{SYMCLI_CONNECT} = setsym($ssid);
         $ENV{SYMCLI_CONNECT} = $site;
         close(INFO);
           if ($debug) {
              printf("...site = %s\n", $site);
              printf("...leave setsym\n");
           }
         return $site;
      }
   }

   close(INFO);
}


sub csco_or_brcd {

   if ($debug) {
      printf("...enter csco_or_brcd\n");
   }

$exp->spawn("ssh  $switch");
$exp->expect($timeout,
        [ "Are you sure you want to continue connecting (yes/no)?" => sub {$_[0]->send("yes\r"); exp_continue; } ],
        [ "Password:" => sub {$_[0]->send("$password\r") ; $sw_vendor = "csco" ; exp_continue ; } ],
        [ "password:" => sub {$_[0]->send("$rpassword\r"); $sw_vendor = "brcd"; exp_continue; } ],
	'-re', qr'[#>:] $',
      );

if ($sw_vendor eq "csco") {
	$exp->expect($timeout, [ $prompt => sub { $_[0]->send("exit\r"); } ]);
}

if ($sw_vendor eq "brcd") {
	$exp->expect($timeout, [ $prompt => sub { $_[0]->send("logout\r"); } ]);
}

   if ($debug) {
      printf("...sw_vendor = %s\n", $sw_vendor);
      printf("...leave csco_or_brcd\n");
   }

return $sw_vendor;

}


sub get_csco_info {

$exp->spawn("ssh  $switch");
$exp->expect($timeout,
        [ "Are you sure you want to continue connecting (yes/no)?" => sub {$_[0]->send("yes\r"); exp_continue; } ],
        [ "assword:" => sub {$_[0]->send("$password\r"); exp_continue; } ],
);


$exp->expect($timeout, [ $prompt => sub { $_[0]->send("term len 0\r"); } ]);
$exp->expect($timeout, [ $prompt => sub { $_[0]->send("term len 0\r"); } ]);

$sport = $port;

$exp->expect($timeout, [ $prompt => sub { $_[0]->send("show interface $sport\r"); } ]);
$exp->expect($timeout, [ '-re', "$sport is ([a-z]+)" => sub {printf("%s\t", ($exp->matchlist)[0]); }]);


$exp->expect($timeout, [ $prompt => sub { $_[0]->send("show flogi data int $sport\r"); } ]);
$exp->expect($timeout, [ '-re', '^fc[0-9/]+\W+[0-9]+\W+0x[0-9a-f]+\W+([0-9a-f:]+)\W+' => sub {$pwwn = ($exp->matchlist)[0]; printf("%s\t", $pwwn); }]);
$exp->expect($timeout, [ '-re', '^\W+\[([0-9A-Za-z\-]+)\]' => sub {$alias = ($exp->matchlist)[0]; printf("%s\n", $alias); }]);


$exp->expect($timeout, [ $prompt => sub { $_[0]->send("show zoneset active | include $alias p 2 n 2\r"); } ]);
$exp->expect($timeout, [ '-re', 'zone name\W+([A-Za-z0-9_\-]+)\W+' => sub {$zone = ($exp->matchlist)[0]; printf("  zone name: %s", $zone); }]);
$exp->expect($timeout, [ '-re', '(\W+\**\W*fcid 0x[0-9a-f]+\W+\[.*\]\W*)' => sub {$tmp = ($exp->matchlist)[0]; printf("%s", $tmp); }]);
$exp->expect($timeout, [ '-re', '(\W+\**\W*fcid 0x[0-9a-f]+\W+\[.*\]\W*)' => sub {$tmp = ($exp->matchlist)[0]; printf("%s\n", $tmp); }]);

$exp->expect($timeout, [ $prompt => sub { $_[0]->send("show log | include $sport\r"); } ]);

$exp->expect($timeout, [ $prompt => sub { $_[0]->send("exit\r"); } ]);
}


sub get_portidx {

$exp->expect($timeout, [ $prompt => sub { $_[0]->send("switchshow\r"); } ]);
$exp->expect($timeout, [ '-re', "\\W*([0-9]+)\\W+$bslot\\W+$bport\\W+" => sub {$portidx = ($exp->matchlist)[0]; }]);

}



sub get_brcd_info {

$exp->spawn("ssh -l root $switch");

$exp->expect($timeout,
	[ "Are you sure you want to continue connecting (yes/no)?" => sub {$_[0]->send("yes\r"); exp_continue; } ],
	[ "password:" => sub {$_[0]->send("$rpassword\r"); exp_continue; } ],
);

get_portidx;

$exp->expect($timeout, [ $prompt => sub { $_[0]->send("portshow $bslot/$bport\r"); } ]);
$exp->expect($timeout, [ '-re', 'portHealth: ([A-Z]+)' => sub {printf("%s\t", ($exp->matchlist)[0]); }]);

printf("%s\t", $hba_pwwn);

$exp->expect($timeout, [ $prompt => sub { $_[0]->send("nodefind $hba_pwwn\r"); } ]);
$exp->expect($timeout, [ '-re', 'Aliases:\W+([0-9A-Za-z]+)' => sub {$alias = ($exp->matchlist)[0]; printf("%s\n", $alias); }]);

$exp->expect($timeout, [ $prompt => sub { $_[0]->send("cfgactvshow | grep $alias -A 2\r"); } ]);
$exp->expect($timeout, [ '-re', '\W+zone:\W+([A-Za-z0-9_]+)\W+' => sub {$tmp = ($exp->matchlist)[0]; printf("  zone: %s\n", $tmp); }]);
$exp->expect($timeout, [ '-re', '\W+([A-Fa-f0-9:]+)+' => sub {$tmp = ($exp->matchlist)[0]; printf("  * %s\n", $tmp); }]);
$exp->expect($timeout, [ '-re', '\W+([A-Fa-f0-9:]+)+' => sub {$tmp = ($exp->matchlist)[0]; printf("  * %s\n\n", $tmp); }]);

$exp->expect($timeout, [ $prompt => sub { $_[0]->send("nszonemember $hba_pwwn\r"); } ]);


$exp->expect($timeout, [ $prompt => sub { $_[0]->send(qq+fabriclog -s | grep -E " $portidx |^[MTWFS]"\r+); } ]);

$exp->expect($timeout, [ $prompt => sub { $_[0]->send("exit\r"); } ]);

}



###
### Main
###

if ($debug) {
   printf("...enter main\n");
}


setsym($ssid);

@tmp = `/usr/symcli/bin/symmask -sid $ssid list logins -wwn $emcpwwn $tee`;

my $i = 0;

while ($i < @tmp) {


   if ($debug) {
      printf("...main: i = %d, tmp[%d] = %s", $i, $i, $tmp[$i]);
   }


if ($tmp[$i] =~ /No device masking login history records could be found/) {
   printf("no device masking login history records could be found for ssid = %s\n", $ssid);
   exit();
}

if ($tmp[$i] =~ /Director Identification : FA-([0-9]+)([A-H]+)\W+/ ) {
   $fanum = $1;
   $faletter = $2;
   if (length($fanum) == 1) {
      $fanum = sprintf("0%s", $fanum);
   }
   printf("length of string is = %d, FA: %s%s\n", length($fanum), $fanum, $faletter);
}
if ($tmp[$i] =~ /Director Port\W+: ([0-9]+)\W+/ ) {
   $faport = $1;
   $fa = sprintf("\"FA-%s%s Port: %s\"", $fanum, $faletter, $faport);
   printf("FA String is %s\n", $fa);
}

if ($tmp[$i] =~ /Fibre/) {
   ($j1, $j2, $j3, $j4, $j5, $j6, $j7) = split(/\W+/, $tmp[$i]);
   if ($debug) {
      printf("j6 (logged in) = %s\n", $j6);
   }
}

$i++;
}


open(ARRAY, "Storage/array_switch_$ssid") || die "could not open array_switch file\n";

while (<ARRAY>) {
   if (/^.*($ssid).*($fa).*"(50:[0-9A-F:]+)","([a-z0-9]+)".*(fc[0-9\/]+)\"/) {
      $stg_pwwn = $3;
      $switch = $4;
      $port = $5;
      $brcd_port = substr($port, 2, length($port) - 2);
      ($bslot, $bport) = split(/\//, $brcd_port);
      printf("ssid = %s\nfa = %s\npwwn = %s\nswitch = %s\nport = %s\nbrcd_port = %s/%s\n", $ssid, $fa, $stg_pwwn, $switch, $port, $bslot, $bport);
   }
}

$exp = new Expect();
$exp->raw_pty(1);
$exp->log_file($outfile);

$swtype = csco_or_brcd();
printf("Switch is %s\n", $sw_vendor);

$exp = new Expect();
$exp->raw_pty(1);
$exp->log_file($outfile);

if ($swtype eq "csco") {
	get_csco_info ();
}

if ($swtype eq "brcd") {
	get_brcd_info ();
}

$exp->log_file(undef);
$exp->soft_close();
