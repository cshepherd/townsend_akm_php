<?php
/**
 * AKMEncryption.php - Singleton class to implement Townsend Security Alliance Key Manager (AKM) Encryption Service API
 *
 * Supports: CBC, Multiple operations per connection
 * Doesn't support: ECB, Packed responses, Continuations
 *
 */
class AKMEncryption
{
	private static $_instance;

	private $host;
	private $port;
	private $cert_file;
	private $ca_file;

	const DEFAULT_PORT = 6003;

	const ENCODING_HEX = 'B16';
	const ENCODING_BASE64 = 'B64';
	const ENCODING_BINARY = 'BIN';

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

	public function CBC_Encrypt( $plaintext, $options, $persistent=false, $final=false )
	{
		$host		= $this->host;
		$port		= $this->port;
		$cert_file	= $this->cert_file;
		$ca_file 	= $this->ca_file;

		$instance = '';
		$ciphertext_encoding = self::ENCODING_BINARY;
		$first_request = false;

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
			if( $options['iv'] )
			{
				$iv = $options['iv'];
			}
			if( $options['key_name'] )
			{
				$key_name = $options['key_name'];
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
			if( $options['ciphertext_encoding'] )
			{
				$ciphertext_encoding = $options['ciphertext_encoding'];
			}
		}

		if( !$fp )
		{
			$first_request = true;
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

		if( !$persistent )
		{
			$is_final = 'Y';
		} else {
			if( $final )
			{
				$is_final = 'Y';
			} else {
				$is_final = 'N';
			}
		}
		if( $first_request )
		{
			$preamble = '000982019';
		} else {
			$preamble = '';
		}
		$request = sprintf("%sY7%s%05dYN%sY%-16s%-40s%24s%s", $preamble, $ciphertext_encoding, strlen( $plaintext ), $is_final, $iv, $key_name, $instance, $plaintext);
		fputs( $fp, $request );
		
		if( $first_request )
		{
			$len = fread( $fp, 5 );
		} else {
			$len = 39-4;
		}
		if( $len )
		{
			$header = fread( $fp, $len );
			if( !$first_request )
			{
				$header = '2020'.$header;
			}
			$error_code = substr( $header, 4, 4 );

			if( $error_code == '0000' )
			{
				$ciphertext_length = substr( $header, 10, 5 );
				$result_instance = substr( $header, 15, 24 );

				$result = fread( $fp, $ciphertext_length );

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
	
	public function CBC_Decrypt( $ciphertext, $options, $persistent=false, $final=false )
	{
		$host		= $this->host;
		$port		= $this->port;
		$cert_file	= $this->cert_file;
		$ca_file 	= $this->ca_file;

		$instance = '';
		$ciphertext_encoding = self::ENCODING_BINARY;
		$plaintext_encoding = self::ENCODING_BINARY;
		$first_request = false;

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
			if( $options['iv'] )
			{
				$iv = $options['iv'];
			}
			if( $options['key_name'] )
			{
				$key_name = $options['key_name'];
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
			if( $options['ciphertext_encoding'] )
			{
				$ciphertext_encoding = $options['ciphertext_encoding'];
			}
			if( $options['plaintext_encoding'] )
			{
				$plaintext_encoding = $options['plaintext_encoding'];
			}
		}

		if( !$fp )
		{
			$first_request = true;
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

		if( !$persistent )
		{
			$is_final = 'Y';
		} else {
			if( $final )
			{
				$is_final = 'Y';
			} else {
				$is_final = 'N';
			}
		}
		if( $first_request )
		{
			$preamble = '001012021';
		} else {
			$preamble = '';
		}
		$request = sprintf("%sYN%s%05d%sYN%sY%-16s%-40s%24s%s", $preamble, $ciphertext_encoding, strlen( $ciphertext ), $plaintext_encoding, $is_final, $iv, $key_name, $instance, $ciphertext);
		fputs( $fp, $request );

		if( $first_request )
		{
			$len = fread( $fp, 5 );
		} else {
			$len = 39-4;
		}
		if( $len )
		{
			$header = fread( $fp, $len );
			if( !$first_request )
			{
				$header = '2022'.$header;
			}
			$error_code = substr( $header, 4, 4 );
			if( $error_code == '0000' )
			{
				$plaintext_length = substr( $header, 10, 5 );
				$result_instance = substr( $header, 15, 24 );

				$result = fread( $fp, $plaintext_length );

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
			throw new Exception( 'decryption reply read error' );
		}
	}
}