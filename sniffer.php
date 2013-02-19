<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Untitled Document</title>
</head>

<body>
<?php
$socket = socket_create(AF_INET , SOCK_RAW , SOL_TCP);  
socket_recv ( $socket , &$buf , 65536 , 0 );
process_packet($buf);

function process_packet($packet)
{
	$ip_header_fmt = 'Cip_ver_len/'
	.'Ctos/'
	.'ntot_len/'                                            
	.'nidentification/'
	.'nfrag_off/'
	.'Cttl/'
	.'Cprotocol/nheader_checksum/Nsource_add/Ndest_add/';
	  
	$ip_header = unpack($ip_header_fmt , $packet);              
	if($ip_header['protocol'] == '6')
  	{
    	tcp_packet($packet);                            
  	}
	if($ip_header['protocol'] == '17')
  	{
    	udp_packet($packet);                           
  	}
}

function tcp_packet($packet)
{
	$ip_header_fmt = 'Cip_ver_len/'
	.'Ctos/'
	.'ntot_len/';                                         
	
	$p = unpack($ip_header_fmt , $packet);
	$ip_len = ($p['ip_ver_len'] & 0x0F);
	
	if($ip_len == 5)
	{
		$ip_header_fmt = 'Cip_ver_len/'
		.'Ctos/'
		.'ntot_len/'
		.'nidentification/'
		.'nfrag_off/'
		.'Cttl/'
		.'Cprotocol/'
		.'nip_checksum/'
		.'Nsource_add/'
		.'Ndest_add/';
  	}
  	else if ($ip_len == 6)
  	{
  		
		$ip_header_fmt = 'Cip_ver_len/'
		.'Ctos/'
		.'ntot_len/'
		.'nidentification/'
		.'nfrag_off/'
		.'Cttl/'
		.'Cprotocol/'
		.'nip_checksum/'
		.'Nsource_add/'
		.'Ndest_add/'
		.'Noptions_padding/';
  	}
  	
  	$tcp_header_fmt = 'nsource_port/'
	.'ndest_port/'
	.'Nsequence_number/'
	.'Nack_no/'
	.'Coffset_reserved/';
  	
  	$total_packet = $ip_header_fmt.$tcp_header_fmt.'H*data';
  	$p = unpack($total_packet , $packet);
	$tcp_header_len = ($p['offset_reserved'] >> 4);
	if($tcp_header_len == 5)
	{
		
		$tcp_header_fmt = 'nsource_port/'
		.'ndest_port/'
		.'Nsequence_number/'
		.'Nack_no/'
		.'Coffset_reserved/'
		.'Ctcp_flags/'
		.'nwindow_size/'
		.'nchecksum/'
		.'nurgent_pointer/';
	}
  	else if($tcp_header_len == 6)
  	{
		$tcp_header_fmt = 'nsource_port/'
		.'ndest_port/'
		.'Nsequence_number/'
		.'Nack_no/'
		.'Coffset_reserved/'
		.'Ctcp_flags/'
		.'nwindow_size/'
		.'nchecksum/'
		.'nurgent_pointer/'
		.'Ntcp_options_padding/';
  	}
  	$total_packet = $ip_header_fmt.$tcp_header_fmt.'H*data';  
	$packet = unpack($total_packet , $packet);
  	$sniffer = array(
	
		'ip_header' => array(
			'ip_ver' => ($packet['ip_ver_len'] >> 4) ,
			'ip_len' => ($packet['ip_ver_len'] & 0x0F) ,
			'tos' => $packet['tos'] ,
			'tot_len' => $packet['tot_len'] ,
			'identification' => $packet['identification'] ,
			'frag_off' => $packet['frag_off'] ,
			'ttl' => $packet['ttl'] ,
			'protocol' => $packet['protocol'] ,
			'checksum' => $packet['ip_checksum'] ,
			'source_add' => long2ip($packet['source_add']) ,
			'dest_add' => long2ip($packet['dest_add']) ,
			'pay_load' => $packet['data'] ,
		) ,
  );
  
  function udp_packet($packet)
  {
$sniffer = array(
		'udp_header' => array(
			'source_port' => $packet['source_port'] ,
			'dest_port' => $packet['dest_port'] ,
			'udp_header_length' => ($packet['offset_reserved'] >> 4) ,
			'checksum' => $packet['ip_checksum'] ,
			'H.data' => $packet['data'],
			'checksum' => $packet['checksum'] . ' [0x'.dechex($packet['checksum']).']',
		) ,
  	);
}
	$count_my_packets = ("counter.txt");
	$hits = file($no_packet);
	$hits[0] ++;
	$fp = fopen($no_packet , "w");
	fputs($fp , "$hits[0]");
	fclose($fp);
	
	$mimes = array(
    'text/plain',
    'text/anytext'
   );

if (in_array($im, $mimes)) 
{
    echo("data is text/n");
}
else
{
	echo("data is image/n");
}
$ip_version = $array['ip_ver'];
if ($ip_version ==4)
{	
	echo "The packet contains IPV4 address/n"; }
	else
	{	
	echo "The packet contains IPV6 address/n";
	}
$fragment = $array['frag_off'];
if ($fragment == 1)
{
	echo "there are no fragments to this packet/n";
}
	else
	{
		echo "there are fragments to this packet/n";
	}
	
$check = $array['checksum'];
if ($check == 0)
{
	echo "Checksum validated/n";
	}
	else
	{
		echo "Something seems wrong!! checksum incorrect/n";
		}
		
echo "Source address is " + $array['source_add'] +"/nDestination address is"+ $array['dest_add']+ "/nSource port is"+ $array['source_port']+ "/nDestination address is"+ $array['dest_port'];

if($buf !=0)
{
	$time = getdate();
	echo "The time when the packet no." +$hits+ "from the ip address"+ $array['source_add']+" arrived is" + $time;
}
		
	echo $hits[0];
	print_r($sniffer);
}
echo "<table>
<tr><td>$packet[ip_ver_len]</td></tr>
	sleep(1);
	<tr><td>$packet[ip_ver_len]</td></tr>
	sleep(1);
	<tr><td>$packet[tos]</td></tr>
	sleep(1);
	<tr><td>$packet[tot_len]</td></tr>
	sleep(1);
	<tr><td>$packet[identification]</td></tr>
	sleep(1);
	<tr><td>$packet[frag_off]</td></tr>
	sleep(1);
	<td><tr>$packet[ttl]</tr></td>
	sleep(1);
	<tr><td>$packet[protocol]</td></tr>
	sleep(1);
	<tr><td>$packet[ip_checksum]</td></tr>
	sleep(1);
	<tr><td>$packet[source_add]</td></tr>
	sleep(1);
	<tr><td>$packet[dest_add]</td></tr>
	sleep(1);
	<tr><td>$packet[data]</td></tr>";

echo "</table>";
?>
</body>
</html>