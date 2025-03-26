<?php

namespace MonoVM\WhoisPhp;

use Exception;

class Whois {
	protected array $definitions = [];

	protected string $socketPrefix = 'socket://';

	public function __construct() {
		$this->load();
	}

	protected function load(): void {
		$path              = __DIR__ . '/dist.whois.json';
		$overridePath      = __DIR__ . '/whois.json';
		$this->definitions = array_merge( $this->parseFile( $path ),
			$this->parseFile( $overridePath ) );
	}

	protected function parseFile( $path ): array {
		$return = [];
		if ( file_exists( $path ) ) {
			$definitions = file_get_contents( $path );
			if ( $definitions = @json_decode( $definitions, TRUE ) ) {
				foreach ( $definitions as $definition ) {
					$extensions = explode( ',', $definition['extensions'] );
					unset( $definition['extensions'] );
					foreach ( $extensions as $extension ) {
						$return[ $extension ] = $definition;
					}
				}
			} else {
				throw new \RuntimeException( 'dist.whois.json file not found!' );
			}
		}

		return $return;
	}

	public function getSocketPrefix(): string {
		return $this->socketPrefix;
	}

	public static function convertTld( string $tld ): string {
		if ( preg_match( '~[^\w.-]~', $tld ) ) {
			$tld = '.' . idn_to_ascii( substr( $tld, 1 ) );
		} elseif ( stripos( $tld, 'xn-' ) === 1 ) {
			$tld = '.' . idn_to_utf8( substr( $tld, 1 ) );
		}

		return $tld;
	}

	public function canLookup( $tld ): bool {
		$hasTldInDefinitions = array_key_exists( $tld, $this->definitions );
		if ( !$hasTldInDefinitions ) {
			$hasTldInDefinitions = array_key_exists( self::convertTld( $tld ), $this->definitions );
		}

		return $hasTldInDefinitions;
	}

	public function getFromDefinitions( $tld, $key ) {
		if ( !isset( $this->definitions[ $tld ] ) ) {
			$tld = self::convertTld( $tld );
		}

		return $this->definitions[ $tld ][ $key ] ?? '';
	}

	protected function getUri( $tld ) {
		if ( $this->canLookup( $tld ) ) {
			$uri = $this->getFromDefinitions( $tld, 'uri' );
			if ( empty( $uri ) ) {
				throw new \RuntimeException( 'Uri not defined for whois service' );
			}

			return $uri;
		}
		throw new \RuntimeException( 'Whois server not known for ' . $tld );
	}

	protected function isSocketLookup( $tld ): bool {
		if ( $this->canLookup( $tld ) ) {
			$uri = $this->getUri( $tld );

			return strpos( $uri, $this->getSocketPrefix() ) === 0;
		}
		throw new \RuntimeException( 'Whois server not known for ' . $tld );
	}

	protected function getAvailableMatchString( $tld ) {
		if ( $this->canLookup( $tld ) ) {
			return $this->getFromDefinitions( $tld, 'available' );
		}
		throw new \RuntimeException( 'Whois server not known for ' . $tld );
	}

	protected function getPremiumMatchString( $tld ) {
		if ( $this->canLookup( $tld ) ) {
			return $this->getFromDefinitions( $tld, 'premium' );
		}
		throw new \RuntimeException( 'Whois server not known for ' . $tld );
	}

	protected function httpWhoisLookup( $domain, $uri ) {
		$url = $uri . $domain;
		$ch  = curl_init();
		curl_setopt( $ch, CURLOPT_URL, $url );
		curl_setopt( $ch, CURLOPT_FOLLOWLOCATION, 0 );
		curl_setopt( $ch, CURLOPT_TIMEOUT, 60 );
		curl_setopt( $ch, CURLOPT_RETURNTRANSFER, 1 );
		curl_setopt( $ch, CURLOPT_SSL_VERIFYHOST, 0 );
		curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, 0 );
		$data = curl_exec( $ch );
		if ( curl_error( $ch ) ) {
			curl_close( $ch );
			throw new Exception( 'Error: ' . curl_errno( $ch ) . ' - ' . curl_error( $ch ), );
		}
		curl_close( $ch );

		return $data;
	}

	protected function socketWhoisLookup( $domain, $server, $port ): string {
		$fp = @fsockopen( $server, $port, $errorNumber, $errorMessage, 10 );
		if ( $fp === FALSE ) {
			throw new \RuntimeException( 'Error: ' . $errorNumber . ' - ' . $errorMessage, );
		}
		@fwrite( $fp, $domain . "\r\n" );
		@stream_set_timeout( $fp, 10 );
		$data = '';
		while ( !@feof( $fp ) ) {
			$data .= @fread( $fp, 4096 );
		}
		@fclose( $fp );

		return $data;
	}

	public function lookup( $parts ) {
		$sld = $parts['sld'];
		$tld = $parts['tld'];

		try {
			$uri                  = $this->getUri( $tld );
			$availableMatchString = $this->getAvailableMatchString( $tld );
			$premiumMatchString   = $this->getPremiumMatchString( $tld );
			$isSocketLookup       = $this->isSocketLookup( $tld );
		} catch ( Exception $e ) {
			return FALSE;
		}
		$domain = $sld . $tld;
		if ( preg_match( '~[^\w.-]~', $domain ) ) {
			$domain = idn_to_ascii( $domain );
		}

		try {
			if ( $isSocketLookup ) {
				$uri  = substr( $uri, strlen( $this->getSocketPrefix() ) );
				$port = 43;
				if ( strpos( $uri, ':' ) ) {
					$port = explode( ':', $uri, 2 );
					[ $uri, $port ] = $port;
				}
				$lookupResult = $this->socketWhoisLookup( $domain,
					$uri,
					$port, );
			} else {
				$lookupResult = $this->httpWhoisLookup( $domain, $uri );
			}
		} catch ( \Exception $e ) {
			$results                = [];
			$results['result']      = 'error';
			$results['errordetail'] = $e->getMessage();

			return $results;
		}
		$lookupResult = ' ---' . $lookupResult;
		$results      = [];
		if ( stripos( $lookupResult, $availableMatchString ) !== FALSE ) {
			$results['result'] = 'available';
		} else {
			if ( $premiumMatchString && stripos( $lookupResult, $premiumMatchString ) !== FALSE ) {
				$results['result'] = 'premium';
			} else {
				$results['result'] = 'unavailable';
				if ( $isSocketLookup ) {
					$results['whois'] = nl2br( htmlentities( $lookupResult ) );
				} else {
					$results['whois'] = nl2br( htmlentities( strip_tags( $lookupResult ) ) );
				}
			}
		}

		return $results;
	}
}
