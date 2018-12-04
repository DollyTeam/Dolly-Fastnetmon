#!/usr/bin/php
<?php
	require_once('apimikrotik.php');

	/*********** Datos de conexión  ***************/
	$ipRouteros="IP";
	$Username="User";
	$Pass="Pass";
	$api_puerto=8728;
	$API = new routeros_api();
	$API->debug = false;
	/********** Datos para el RBTH ***********/
	$provider_RBTH = 'Upstream'; // Choose one or more upstream separated by &nbsp -  "Cogent" or "Cogent-Ntt" or Cogent-NTT-Telia"
	$src_evil = $argv[1];       
	$dst_attack = $argv[2];     
	$switch_RBTH = $argv[4];    

	/**************************************** Mostrar creditos y Ayuda en pantalla ***********************************************/
	$credit = "<br>"."**********************************************************************************************"."<br>";
	$credit .= "* MikroTik RouterOS PHP API integration for FastNetMon "."<br>";
	$credit .= "* This script connect to router MikroTik and add or remove a blackhole's rule for the IP attack"."<br>";
	$credit .= "*<br>";
	$credit .= "<font color='#2673c2'><b>* RTBH MultiUpstream *"."<br>"; 
	$credit .= "* v1.1 - 1 Dec 18 - Startnix version || Author: DollyTeam - foro.startnix.com</b></font>"."<br>"; 
	$credit .= "*<br>";
	$credit .= "* v1.0 - 4 Jul 16 - Initial version || Author: Maximiliano Dobladez"."<br>";
	$credit .= "**********************************************************************************************"."<br><br>";
	echo $credit;

	/**************************************** Creamos texto de ayuda *************************************************************/
	$help = "<b>Command:</b> fastnetmon_mikrotik.php src_evil dst_attacked upstream action"."<br><br>";
	$help .= "&nbsp&nbsp&nbsp src_evil --> 8.8.8.8 &nbsp||&nbsp Specifies the attacking Ip"."<br>";
	$help .= "&nbsp&nbsp&nbsp dst_attacked --> 1.1.1.1 &nbsp||&nbsp Specifies the attacked Ip"."<br>";
	$help .= "&nbsp&nbsp&nbsp upstream --> Cogent or Cogent-NTT or Cogent-NTT-Telia &nbsp||&nbsp Choose one or more upstream separated by &nbsp - "."<br>";
	$help .= "&nbsp&nbsp&nbsp action --> ban or unban &nbsp||&nbsp Enables or disables the RTBH protection"."<br><br>";
	$help .= "------------------------------------------------------------------------------------------------------------"."<br><br>";


	/* INICIO -  Sanitize input */
	
	if (!preg_match( "/^(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/", $src_evil )) {
	// Mostramos el menu de ayuda en caso de no coincidir o faltar alguna variable
		echo $help;
		echo 'Error: src-evil is not correctly formated. We need a standard 4 Octect IP xxx.xxx.xxx.xxx';
		exit (-1); // si se ejecuta en un script queremos saber que ha habido un error.
	} else {
		echo "src_evil: ".$src_evil."<br>";
	}
	if (!preg_match( "/^(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/", $dst_attack )) {
		echo $help;
		echo 'Error: dst_attacked is not correctly formated. We need a standard 4 Octect IP xxx.xxx.xxx.xxx';
		exit (-1); // si se ejecuta en un script queremos saber que ha habido un error.
	} else {
		echo "dst_attack: ".$dst_attack."<br>";
	}
	if($provider_RBTH == NULL){
		echo $help;
		echo 'Error: provider_RBTH is empty';
		exit (-1); // si se ejecuta en un script queremos saber que ha habido un error.
	} else {
		echo "provider_RBTH: ".$provider_RBTH."<br>";
	}
	if($switch_RBTH == NULL){
		echo $help;
		echo 'Error: switch_RBTH is empty';
		exit (-1); // si se ejecuta en un script queremos saber que ha habido un error.
	} else {
		echo "switch_RBTH: ".$switch_RBTH."<br>";
	}

	/* FIN -  Sanitize input */

	/***************************** Analizamos la variable upstream y extraemos los proveedores *********************/	
	$upstream_input = str_replace("-", ", ", $provider_RBTH);	
	$array_upstream = explode (", ", $upstream_input);
	$community_MT ="";
	$community = "";
	$primero = true;
	foreach ($array_upstream as $upstream) {
		switch ($upstream){
			/***************** Tiers1 ****************************/
			case "NTT": $community = "2914:666"; break;
			case "Level3": $community = "3356:9999"; break;
			case "Telia": $community = "1299:999"; break;
			case "C&W": $community = "1273:666"; break; 
			case "Zayo": $community = "6461:5990"; break; 
			case "Sparkle": $community = "6762:666"; break; 
			case "GTT": $community = "3257:2666"; break;
			case "Verizon": $community = "701:9999"; break;
			/***************** Tiers2 /IXP ************************/
			case "Init7": $community = "65000:666"; break;
			case "Core-Backbone": $community = "33891:33890"; break;
			case "Colt": $community = "8220:63999"; break; 
			case "Rent": $community = "9002:666"; break;
			case "Comcast": $community = "7922:666"; break;
			case "Cogent": $community = "174:990"; break;	//Do not send route to BGP customers, or peers.
			case "HE": $community = "6939:666"; break;	
		}	
		if (!$primero) {
			$separador =",";
		} else {
			$primero = false;
			$separador ="";
		}
		$community_MT .= $separador.$community;	// Community para insertar en Mikrotik
	}
	/***************************************************************************************************************/

	/************************************ Ejecutamos el RBTH en el Mikrotik ****************************************/
	if ($API->connect($ipRouteros , $Username , $Pass, $api_puerto)) {
	//					un switch es más eficiente y permite añadir acciones sin mucha alteración del código
		switch ($switch_RBTH) { 
		//Add Blocking by route blackhole
			case "ban":
				$comment = 'FastNetMon Guard: IP ' . $dst_attack . ' is attacked by '.$src_evil;
				$API->write( '/ip/route/add', false );
				$API->write( '=dst-address=' . $dst_attack, false );
				$API->write( '=type=blackhole', false );
				$API->write( '=bgp-communities='.$community_MT.'', false );
				$API->write( '=comment=' . $comment, true );
				$API->read();
				echo '<font color="#4fea35"><b>Apply RTBH to Upstream --> </b></font> [ '.$upstream_input. ' ] for IP '.$dst_attack;
			break;
		/******************************** Borramos el RBTH  del Mikrtoik ********************/
			case "unban":
				$API->write( '/ip/route/print', false );
				$API->write( '?dst-address=' . $dst_attack . "/32" );
				$ID_ARRAY = $API->read();
				// Sino existe el RTBH a esa IP no la podemos borrar
				if($ID_ARRAY !=NULL){
					$API->write('/ip/route/remove', false);
					$API->write('=.id='.$ID_ARRAY[0]['.id']);
					$API->read();
					echo '<font color="#4fea35"><b>Remove RTBH to Upstream --></b></font> [ '.$upstream_input. ' ] for IP '.$dst_attack;
				} else {
					echo '<font color="#ea4335"><b>Error: Prefix does not exist in the BlackHole list</b></font>';
				}
			break;
		// Acciones posibles, ban o unban, para la variable action
			default:
				echo $help;
				echo '<font color="#ea4335"><b>[action] --> The action can only ban or unban</b></font>';
		}
		//				Sólo hay que desconectar si se ha producido una conexión correcta.
		$API->disconnect();
		exit (0); // Salimos sin error.
	} else {
		// No hemos podido conectar con la Api del Router
		/************************************************************************************************/
		/** TODO 																						*/
		/** Controlar el error de salida de la función para entregar el error como salida y no dar		*/
		/** un error genérico																			*/
		/************************************************************************************************/
		echo '<font color="#ea4335"><b>We could not connect to your router, check the connection data and port api</b></font>';	
		exit (-1); // si se ejecuta en un script queremos saber que ha habido un error.
	}
	/***************************************************************************************************************/

?>
