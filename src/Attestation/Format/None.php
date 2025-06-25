<?php


namespace Onetech\WebAuthn\Attestation\Format;

use Onetech\WebAuthn\Attestation\AuthenticatorData;

class None extends FormatBase
{


    public function __construct($AttentionObject, AuthenticatorData $authenticatorData)
    {
        parent::__construct($AttentionObject, $authenticatorData);
    }


    /*
     * returns the key certificate in PEM format
     * @return string
     */
    public function getCertificatePem(): ?string
    {
        return null;
    }

    /**
     * @param string $clientDataHash
     * @return true
     */
    public function validateAttestation(string $clientDataHash): bool
    {
        return true;
    }

    /**
     * validates the certificate against root certificates.
     * Format 'none' does not contain any ca, so always false.
     * @param array $rootCas
     * @return boolean
     */
    public function validateRootCertificate(array $rootCas): bool
    {
        return false;
    }
}
