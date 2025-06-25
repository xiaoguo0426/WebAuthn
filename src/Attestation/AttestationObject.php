<?php

namespace Onetech\WebAuthn\Attestation;

use Onetech\WebAuthn\Attestation\Format\FormatBase;
use Onetech\WebAuthn\WebAuthnException;
use Onetech\WebAuthn\CBOR\CborDecoder;
use Onetech\WebAuthn\Binary\ByteBuffer;

/**
 * @author Lukas Buchs
 * @license https://github.com/lbuchs/WebAuthn/blob/master/LICENSE MIT
 */
class AttestationObject
{
    private AuthenticatorData $_authenticatorData;
    private FormatBase $_attestationFormat;
    private string $_attestationFormatName;

    /**
     * @throws WebAuthnException
     */
    public function __construct($binary, $allowedFormats)
    {
        $enc = CborDecoder::decode($binary);
        // validation
        if (!\is_array($enc) || !\array_key_exists('fmt', $enc) || !is_string($enc['fmt'])) {
            throw new WebAuthnException('invalid attestation format', WebAuthnException::INVALID_DATA);
        }

        if (!\array_key_exists('attStmt', $enc) || !\is_array($enc['attStmt'])) {
            throw new WebAuthnException('invalid attestation format (attStmt not available)', WebAuthnException::INVALID_DATA);
        }

        if (!\array_key_exists('authData', $enc) || !\is_object($enc['authData']) || !($enc['authData'] instanceof ByteBuffer)) {
            throw new WebAuthnException('invalid attestation format (authData not available)', WebAuthnException::INVALID_DATA);
        }

        $this->_authenticatorData = new AuthenticatorData($enc['authData']->getBinaryString());
        $this->_attestationFormatName = $enc['fmt'];

        // Format ok?
        if (!in_array($this->_attestationFormatName, $allowedFormats)) {
            throw new WebAuthnException('invalid attestation format: ' . $this->_attestationFormatName, WebAuthnException::INVALID_DATA);
        }


        $this->_attestationFormat = match ($this->_attestationFormatName) {
            'android-key' => new Format\AndroidKey($enc, $this->_authenticatorData),
            'android-safetynet' => new Format\AndroidSafetyNet($enc, $this->_authenticatorData),
            'apple' => new Format\Apple($enc, $this->_authenticatorData),
            'fido-u2f' => new Format\U2f($enc, $this->_authenticatorData),
            'none' => new Format\None($enc, $this->_authenticatorData),
            'packed' => new Format\Packed($enc, $this->_authenticatorData),
            'tpm' => new Format\Tpm($enc, $this->_authenticatorData),
            default => throw new WebAuthnException('invalid attestation format: ' . $enc['fmt'], WebAuthnException::INVALID_DATA),
        };
    }

    /**
     * returns the attestation format name
     * @return string
     */
    public function getAttestationFormatName(): string
    {
        return $this->_attestationFormatName;
    }

    /**
     * returns the attestation format class
     * @return FormatBase
     */
    public function getAttestationFormat(): FormatBase
    {
        return $this->_attestationFormat;
    }

    /**
     * returns the attestation public key in PEM format
     * @return AuthenticatorData
     */
    public function getAuthenticatorData(): AuthenticatorData
    {
        return $this->_authenticatorData;
    }

    /**
     * returns the certificate chain as PEM
     * @return string|null
     */
    public function getCertificateChain(): ?string
    {
        return $this->_attestationFormat->getCertificateChain();
    }

    /**
     * return the certificate issuer as string
     * @return string
     */
    public function getCertificateIssuer(): string
    {
        $pem = $this->getCertificatePem();
        $issuer = '';
        if ($pem) {
            $certInfo = \openssl_x509_parse($pem);
            if (\is_array($certInfo) && \array_key_exists('issuer', $certInfo) && \is_array($certInfo['issuer'])) {

                $cn = $certInfo['issuer']['CN'] ?? '';
                $o = $certInfo['issuer']['O'] ?? '';
                $ou = $certInfo['issuer']['OU'] ?? '';

                if ($cn) {
                    $issuer .= $cn;
                }
                if ($issuer && ($o || $ou)) {
                    $issuer .= ' (' . trim($o . ' ' . $ou) . ')';
                } else {
                    $issuer .= trim($o . ' ' . $ou);
                }
            }
        }

        return $issuer;
    }

    /**
     * return the certificate subject as string
     * @return string
     */
    public function getCertificateSubject(): string
    {
        $pem = $this->getCertificatePem();
        $subject = '';
        if ($pem) {
            $certInfo = \openssl_x509_parse($pem);
            if (\is_array($certInfo) && \array_key_exists('subject', $certInfo) && \is_array($certInfo['subject'])) {

                $cn = $certInfo['subject']['CN'] ?? '';
                $o = $certInfo['subject']['O'] ?? '';
                $ou = $certInfo['subject']['OU'] ?? '';

                if ($cn) {
                    $subject .= $cn;
                }
                if ($subject && ($o || $ou)) {
                    $subject .= ' (' . trim($o . ' ' . $ou) . ')';
                } else {
                    $subject .= trim($o . ' ' . $ou);
                }
            }
        }

        return $subject;
    }

    /**
     * returns the key certificate in PEM format
     * @return string
     */
    public function getCertificatePem(): ?string
    {
        return $this->_attestationFormat->getCertificatePem();
    }

    /**
     * checks validity of the signature
     * @param string $clientDataHash
     * @return bool
     * @throws WebAuthnException
     */
    public function validateAttestation(string $clientDataHash): bool
    {
        return $this->_attestationFormat->validateAttestation($clientDataHash);
    }

    /**
     * validates the certificate against root certificates
     * @param array $rootCas
     * @return boolean
     * @throws WebAuthnException
     */
    public function validateRootCertificate(array $rootCas): bool
    {
        return $this->_attestationFormat->validateRootCertificate($rootCas);
    }

    /**
     * checks if the RpId-Hash is valid
     * @param string $rpIdHash
     * @return bool
     */
    public function validateRpIdHash(string $rpIdHash): bool
    {
        return $rpIdHash === $this->_authenticatorData->getRpIdHash();
    }
}
