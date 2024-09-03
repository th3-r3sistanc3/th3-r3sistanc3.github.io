<!--
Parse nmap XML output
	Koen Van Impe		cudeso.be
	http://www.vanimpe.eu/2010/03/03/nmap-xml-to-html-parser/
	20100303
	
	Modified by: Rahul Ghule
-->
<html>
<head>
	<title>nmap xml file to html</title>
	<style type="text/css">
	table, td, th {
		border-bottom: 1px solid rgb(79,129,189);
		outline-style: 1px solid;
		font-family: Calibri;
		font-size: 14.26px;
		
	}
	th {
		background-color: rgb(79,129,189);
		color:white;
	}
  tr:nth-child(even) {
    background-color: rgb(211,223,238);
  }
	table {
		border-collapse:collapse;
		
		width:6.2in;
	}
	#port
	{
		border-left: 1px solid #4F81BD;
		border-right: 1px solid #4F81BD;
		font-family: Calibri;
		
	}
	#IP_Font
	{
		font-family: Calibri;
		font-size: 14.667px;
		
	}


		</style>
	<style type="text/css">
	.odd {
	background-color:FFFFFF;
	
	}
	
	.even{
	
	background-color:white;
	}
	
	

</style>
</head>
<body>
	<form method="POST" enctype="multipart/form-data" action="<?php echo $_SERVER["PHP_SELF"]; ?>">
		XML file: 
			<input type="file" name="xmlfile[]" multiple> <br />
			<!--<input type="checkbox" checked name="open"> Open <br />
			<input type="checkbox"  name="closed"> Closed <br />
			<input type="checkbox"  name="filtered"> Filtered <br /> -->
			<input type="submit" value="Press"> to upload the file!
	</form>
<?php
	error_reporting(0);
	if(isset($_FILES['xmlfile'])) {
	// init
		if (trim($_POST["open"]) == "on")
			$printOpen = true;
		else
			$printOpen = false;
		if (trim($_POST["closed"]) == "on")
			$printClosed = true;
		else
			$printClosed = false;
		if (trim($_POST["filtered"]) == "on")
			$printFiltered = true;
		else
			$printFiltered = false;
		$count_of_files = count($_FILES['xmlfile']['tmp_name']);
		print "There are: ".$count_of_files." files";
		echo"</br>";
		$zero_open_ports_ip = array();
		for($i=0;$i<$count_of_files;$i++)
		{
			#print "Inside For loop";
			#echo $i;
			$xmlObject = simplexml_load_file($_FILES['xmlfile']['tmp_name'][$i]);
		// run through the xml and print hostinfo
			
			foreach($xmlObject as $host => $value) {
		// Only grab the data if it's host related info
				
				if ((string) $host == "host") {
					// declare portsarray
					$nmap["ports"] = array();

					 //modified by JIT
					 $NoOpenPorts = true;
					foreach ($value->ports->port as $port) {
					 	if((string)$port->state["state"] == "open"){
							$NoOpenPorts=false;
						 	break;	
						 }
					}
					if($NoOpenPorts == true){
						$zero_open_ports_ip[count($zero_open_ports_ip)] = (string) $value->address["addr"];
						continue;
					}
	
				// get the hostinfo
				echo "</br><span id='IP_Font'>IP Address: ".(string) $value->address["addr"]."</span>";
				//			" (".(string) $value->address["addr"]." / ".(string) $value->address["addrtype"].")</h2>";
				//			" -- ".(string) $value->hostnames->hostname["name"]."</h2>";
				echo "<table id='Port'>";
	
				// put the discovered ports in an array
				
				echo '<tr ><th>Port</th><th>Protocol</th><th>Service Running</th><th>Service Version Details</th>';
				        $open_ports_count=0; //modified by ajay
					foreach ($value->ports->port as $port) {
					 	if((string)$port->state["state"] == "open"){
						//modification done by ajay//
						$open_ports_count=$open_ports_count+1;
						
						//modifcation done by ajay//
						echo ($open_ports_count % 2)?'<tr   class="odd">':'<tr  class="even">';
						echo "<td align=center>".(string)$port["portid"]."</td><td align=center>".(string) strtoupper($port["protocol"])."</td>".
								
								"<td align=center>".$port->service["name"]."</td><td align=center>".(string)$port->service["product"]." ".(string)$port->service["version"]."</td>
									</tr>";
						}
					}
					echo "</table>";
				}
			}
			
			
		}
		if(count($zero_open_ports_ip)>0){
			echo "</br><span id='IP_Font'><b>Note:</b> During the vulnerability assessment all the ports appeared to be CLOSED or FILTERED on the IP addresses mentioned below.</span>";
			for($x = 0; $x < count($zero_open_ports_ip); $x++) {
				echo "</br><span id='IP_Font'>".(string) $zero_open_ports_ip[$x]."</span>";
			  }
			}
	}	
?>
</body>
</html>

