<?php

namespace MonoVM\WhoisPhp;

class WhoisHandler {
	private string $sld;
	private string $tld;
	private bool   $isAvailable = FALSE;
	private bool   $isValid     = TRUE;
	private string $whoisMessage;

	private Whois $whois;

	/**
	 * Handler construct.
	 */
	protected function __construct( ?string $domain = NULL ) {
		$this->whois = new Whois();
		if ( $domain ) {
			$this->lookup( $domain );
		}
	}

	private function lookup( string $domain ): void {
		$domainParts = explode( '.', $domain, 2 );
		$this->sld   = $domainParts[0];
		$this->tld   = '.' . $domainParts[1];

		if ( $this->whois->canLookup( $this->tld ) ) {
			$result = $this->whois->lookup( [ 'sld' => $this->sld, 'tld' => $this->tld ] );
			if ( !isset( $result['whois'] ) && strtolower( $result['result'] ) === 'available' ) {
				$this->whoisMessage = $domain . ' is available for registration.';
				$this->isAvailable  = TRUE;
			} else {
				$this->whoisMessage = $result['whois'];
			}
		} else {
			$this->whoisMessage = 'Unable to lookup whois information for ' . $domain;
			$this->isValid      = FALSE;
		}
	}

	/**
	 * Starts the whois operation.
	 */
	public static function whois( string $domain ): WhoisHandler {
		return new self( $domain );
	}

	/**
	 * Returns Top-Level Domain.
	 */
	public function getTld(): string {
		return $this->tld;
	}

	/**
	 * Returns Second-Level Domain.
	 */
	public function getSld(): string {
		return $this->sld;
	}

	/**
	 * Determines if the domain is available for registration.
	 */
	public function isAvailable(): bool {
		return $this->isAvailable;
	}

	/**
	 * Determines if the domain can be looked up.
	 */
	public function isValid(): bool {
		return $this->isValid;
	}

	/**
	 * Returns the whois server message.
	 */
	public function getWhoisMessage(): string {
		return $this->whoisMessage;
	}
}
