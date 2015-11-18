<?php
	require_once( 'AKMEncryption.php' );

// Test 1: 3 Encrypt operations on same connection
	$plaintext = 'woopy woo!';
	echo "plaintext: {$plaintext}\n";

	$encryption = AKMEncryption::getInstance();
	$result = $encryption->CBC_Encrypt( $plaintext, array(
		'host'	=> '10.0.1.16',
		'cert_file'	=> 'keys/client_cert_and_key.pem',
		'ca_file'	=> 'keys/AKMRootCACertificate.pem',
		'key_name'	=> 'AES256',
		'ciphertext_encoding' => AKMEncryption::ENCODING_HEX,
	), true, false );

	print_r( $result );
	$ciphertext1	= $result['result'];
	$instance2	= $result['instance'];
	$fp			= $result['fp'];

	$plaintext = 'woopy woo! test number 2!';
	echo "plaintext: {$plaintext}\n";

	$encryption = AKMEncryption::getInstance();
	$result = $encryption->CBC_Encrypt( $plaintext, array(
		'host'	=> '10.0.1.16',
		'cert_file'	=> 'keys/client_cert_and_key.pem',
		'ca_file'	=> 'keys/AKMRootCACertificate.pem',
		'key_name'	=> 'AES256',
		'ciphertext_encoding' => AKMEncryption::ENCODING_HEX,
		'fp'		=> $fp,
	), true, false );

	print_r( $result );
	$ciphertext2= $result['result'];
	$instance2	= $result['instance'];
	$fp			= $result['fp'];

	$plaintext = 'woopy woo! test number 3!';
	echo "plaintext: {$plaintext}\n";

	$encryption = AKMEncryption::getInstance();
	$result = $encryption->CBC_Encrypt( $plaintext, array(
		'host'	=> '10.0.1.16',
		'cert_file'	=> 'keys/client_cert_and_key.pem',
		'ca_file'	=> 'keys/AKMRootCACertificate.pem',
		'key_name'	=> 'AES256',
		'ciphertext_encoding' => AKMEncryption::ENCODING_HEX,
		'fp'		=> $fp,
	), true, true );

	print_r( $result );

// Test 2: 2 Decrypt operations on same connection
	$result = $encryption->CBC_Decrypt( $ciphertext1, array(
		'host'	=> '10.0.1.16',
		'cert_file'	=> 'keys/client_cert_and_key.pem',
		'ca_file'	=> 'keys/AKMRootCACertificate.pem',
		'key_name'	=> 'AES256',
		'ciphertext_encoding' => AKMEncryption::ENCODING_HEX,
	), true, false );
	print_r( $result );
	$fp			= $result['fp'];

	$result = $encryption->CBC_Decrypt( $ciphertext2, array(
		'host'	=> '10.0.1.16',
		'cert_file'	=> 'keys/client_cert_and_key.pem',
		'ca_file'	=> 'keys/AKMRootCACertificate.pem',
		'key_name'	=> 'AES256',
		'ciphertext_encoding' => AKMEncryption::ENCODING_HEX,
		'fp'		=> $fp,
	), true, true );
	print_r( $result );
