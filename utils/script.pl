#!/usr/bin/perl -w 

$NO_USERS = 100;
$NO_MACHINES = 50;

for($i=1; $i<=$NO_MACHINES+1; $i++) {
    for($j=0; $j<=$NO_USERS; $j++) {
	$str = sprintf("mv %03dnode%d_cert.pem  #%03d#node%d_cert.pem", $j, $i, $j, $i); 
	printf "$str \n";
	system($str);

	$str = sprintf("mv %03dnode%d_priv.pem  #%03d#node%d_priv.pem", $j, $i, $j, $i); 
	printf "$str \n";
	system($str);
    }	
}

