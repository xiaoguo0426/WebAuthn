<?php


namespace Onetech\WebAuthn\Attestation\Format;

use Onetech\WebAuthn\Attestation\AuthenticatorData;
use Onetech\WebAuthn\WebAuthnException;
use Onetech\WebAuthn\Binary\ByteBuffer;

class Apple extends FormatBase
{
    private string $_x5c;

    /**
     * @throws WebAuthnException
     */
    public function __construct($AttentionObject, AuthenticatorData $authenticatorData)
    {
        parent::__construct($AttentionObject, $authenticatorData);

        // check packed data
        $attStmt = $this->_attestationObject['attStmt'];


        // certificate for validation
        if (\array_key_exists('x5c', $attStmt) && \is_array($attStmt['x5c']) && \count($attStmt['x5c']) > 0) {

            // The attestation certificate attestCert MUST be the first element in the array
            $attestCert = array_shift($attStmt['x5c']);

            if (!($attestCert instanceof ByteBuffer)) {
                throw new WebAuthnException('invalid x5c certificate', WebAuthnException::INVALID_DATA);
            }

            $this->_x5c = $attestCert->getBinaryString();

            // certificate chain
            foreach ($attStmt['x5c'] as $chain) {
                if ($chain instanceof ByteBuffer) {
                    $this->_x5c_chain[] = $chain->getBinaryString();
                }
            }
        } else {
            throw new WebAuthnException('invalid Apple attestation statement: missing x5c', WebAuthnException::INVALID_DATA);
        }
    }


    /*
     * returns the key certificate in PEM format
     * @return string|null
     */
    public function getCertificatePem(): ?string
    {
        return $this->_createCertificatePem($this->_x5c);
    }

    /**
     * @param string $clientDataHash
     * @return bool
     * @throws WebAuthnException
     */
    public function validateAttestation(string $clientDataHash): bool
    {
        return $this->_validateOverX5c($clientDataHash);
    }

    /**
     * validates the certificate against root certificates
     * @param array $rootCas
     * @return boolean
     * @throws WebAuthnException
     */
    public function validateRootCertificate(array $rootCas): bool
    {
        $chainC = $this->_createX5cChainFile();
        if ($chainC) {
            $rootCas[] = $chainC;
        }

        $v = \openssl_x509_checkpurpose($this->getCertificatePem(), -1, $rootCas);
        if ($v === -1) {
            throw new WebAuthnException('error on validating root certificate: ' . \openssl_error_string(), WebAuthnException::CERTIFICATE_NOT_TRUSTED);
        }
        return $v;
    }

    /**
     * validate if x5c is present
     * @param string $clientDataHash
     * @return bool
     * @throws WebAuthnException
     */
    protected function _validateOverX5c(string $clientDataHash): bool
    {
        $publicKey = \openssl_pkey_get_public($this->getCertificatePem());

        if ($publicKey === false) {
            throw new WebAuthnException('invalid public key: ' . \openssl_error_string(), WebAuthnException::INVALID_PUBLIC_KEY);
        }

        // Concatenate authenticatorData and clientDataHash to form nonceToHash.
        $nonceToHash = $this->_authenticatorData->getBinary();
        $nonceToHash .= $clientDataHash;

        // Perform SHA-256 hash of nonceToHash to produce nonce
        $nonce = hash('SHA256', $nonceToHash, true);

        $credCert = openssl_x509_read($this->getCertificatePem());
        if ($credCert === false) {
            throw new WebAuthnException('invalid x5c certificate: ' . \openssl_error_string(), WebAuthnException::INVALID_DATA);
        }

        $keyData = openssl_pkey_get_details(openssl_pkey_get_public($credCert));
        $key = is_array($keyData) && array_key_exists('key', $keyData) ? $keyData['key'] : null;


        // Verify that nonce equals the value of the extension with OID ( 1.2.840.113635.100.8.2 ) in credCert.
        $parsedCredCert = openssl_x509_parse($credCert);
        $nonceExtension = $parsedCredCert['extensions']['1.2.840.113635.100.8.2'] ?? '';

        // nonce padded by ASN.1 string: 30 24 A1 22 04 20
        // 30     — type tag indicating sequence
        // 24     — 36 byte following
        //   A1   — Enumerated [1]
        //   22   — 34 byte following
        //     04 — type tag indicating octet string
        //     20 — 32 byte following

        $asn1Padding = "\x30\x24\xA1\x22\x04\x20";
        if (str_starts_with($nonceExtension, $asn1Padding)) {
            $nonceExtension = substr($nonceExtension, strlen($asn1Padding));
        }

        if ($nonceExtension !== $nonce) {
            throw new WebAuthnException('nonce doesn\'t equal the value of the extension with OID 1.2.840.113635.100.8.2', WebAuthnException::INVALID_DATA);
        }

        // Verify that the credential public key equals the Subject Public Key of credCert.
        $authKeyData = openssl_pkey_get_details(openssl_pkey_get_public($this->_authenticatorData->getPublicKeyPem()));
        $authKey = is_array($authKeyData) && array_key_exists('key', $authKeyData) ? $authKeyData['key'] : null;

        if ($key === null || $key !== $authKey) {
            throw new WebAuthnException('credential public key does\'t equal the Subject Public Key of credCert', WebAuthnException::INVALID_DATA);
        }

        return true;
    }

}

