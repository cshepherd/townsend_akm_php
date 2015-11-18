<?php
	require_once( 'AKMKeyService.php' );

// Test 1: GetSymmetricKey
	$keyservice = AKMKeyService::getInstance();
	$result = $keyservice->GetSymmetricKey( 'AES256', array(
		'host'	=> '10.0.1.16',
		'cert_file'	=> 'keys/client_cert_and_key.pem',
		'ca_file'	=> 'keys/AKMRootCACertificate.pem',
	));

	print_r( $result );
	$dek		= $result['result'];
	$instance	= $result['instance'];
