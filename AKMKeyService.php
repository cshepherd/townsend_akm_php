<?php
/**
 * AKMKeyService.php - Singleton class to implement Townsend Security Alliance Key Manager (AKM) Key Service API
 *
 * Supports: GetSymmetricKey
 * Doesn't support: GetNextKey
 *
 */
class AKMKeyService
{
	private static $_instance;

	private $host;
	private $port;
	private $cert_file;
	private $ca_file;

	const DEFAULT_PORT = 6000;

	private function __construct()
	{
		$this->port = self::DEFAULT_PORT;
	}

	static public function getInstance()
	{
		if(is_null(self::$_instance)){
			self::$_instance = new self();
		}
		return self::$_instance;
	}

	public function setHost( $hostname )
	{
		$this->host = $hostname;
	}

	public function setPort( $port )
	{
		$this->port = $port;
	}

	public function setCertFile( $cert_file )
	{
		$this->cert_file = $cert_file;
	}

	public function setCAFile( $ca_file )
	{
		$this->ca_file = $ca_file;
	}

	public function GetSymmetricKey( $key_name, $options )
	{
		$host		= $this->host;
		$port		= $this->port;
		$cert_file	= $this->cert_file;
		$ca_file 	= $this->ca_file;

		$persistent	= false;
		$instance = '';

		if( is_array( $options ))
		{
			if( $options['host'] )
			{
				$host = $options['host'];
			}
			if( $options['port'] )
			{
				$port = $options['port'];
			}
			if( $options['cert_file'] )
			{
				$cert_file = $options['cert_file'];
			}
			if( $options['ca_file'] )
			{
				$ca_file = $options['ca_file'];
			}
			if( $options['fp'] )
			{
				$persistent = true;
				$fp = $options['fp'];
			}
			if( $options['instance'] )
			{
				$instance = $options['instance'];
			}
		}

		if( !$fp )
		{
			$opts = array(
			    'ssl' => array(
			        'cafile' => $ca_file,
					'capture_peer_cert' => true,
					'local_cert' => $cert_file,
					'verify_peer' => true
				)
			);

			$ctx = stream_context_create($opts);

			$fp = stream_socket_client('tls://'.$host.':'.$port, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $ctx);
			if( !$fp )
			{
				throw new Exception( $errno.': '.$errstr );
			}
		}

		$request = sprintf("000712001%-40s%24sBIN", $key_name, $instance);
		fputs( $fp, $request );
		
		$len = fread( $fp, 5 );
		if( $len )
		{
			$response = fread( $fp, $len+100 );		// TODO wrong
			$error_code = substr( $response, 4, 4 );
			if( $error_code == '0000' )
			{
				$result = substr( $response, 95 );
				$result_instance = substr( $response, 48, 24 );

				if( !$persistent )
				{
					fclose( $fp );
				}

				$return = array(
					'result'	=> $result,
					'instance'	=> $result_instance,
				);
				if( $persistent )
				{
					$return['fp'] = $fp;
				}

				return $return;
			} else {
				throw new Exception( 'AKM error '.$error_code );
			}
		} else {
			throw new Exception( 'encryption reply read error' );
		}
	}
}