<?php


namespace Onetech\WebAuthn\Attestation\Format;

use Onetech\WebAuthn\WebAuthnException;
use Onetech\WebAuthn\Attestation\AuthenticatorData;
use stdClass;
use function count;


abstract class FormatBase
{
    protected ?array $_attestationObject;
    protected ?AuthenticatorData $_authenticatorData;
    protected array $_x5c_chain;
    protected $_x5c_tempFile = null;

    /**
     *
     * @param array $AttentionObject
     * @param AuthenticatorData $authenticatorData
     */
    public function __construct(array $AttentionObject, AuthenticatorData $authenticatorData)
    {
        $this->_attestationObject = $AttentionObject;
        $this->_authenticatorData = $authenticatorData;
    }

    /**
     *
     */
    public function __destruct()
    {
        // delete X.509 chain certificate file after use
        if ($this->_x5c_tempFile && \is_file($this->_x5c_tempFile)) {
            \unlink($this->_x5c_tempFile);
        }
    }

    /**
     * returns the certificate chain in PEM format
     * @return string|null
     */
    public function getCertificateChain(): ?string
    {
        if ($this->_x5c_tempFile && \is_file($this->_x5c_tempFile)) {
            return \file_get_contents($this->_x5c_tempFile);
        }
        return null;
    }

    /**
     * returns the key X.509 certificate in PEM format
     * @return string|null
     */
    public function getCertificatePem(): ?string
    {
        // need to be overwritten
        return null;
    }

    /**
     * checks validity of the signature
     * @param string $clientDataHash
     * @return bool
     * @throws WebAuthnException
     */
    public function validateAttestation(string $clientDataHash): bool
    {
        // need to be overwritten
        return false;
    }

    /**
     * validates the certificate against root certificates
     * @param array $rootCas
     * @return boolean
     * @throws WebAuthnException
     */
    public function validateRootCertificate(array $rootCas): bool
    {
        // need to be overwritten
        return false;
    }


    /**
     * create a PEM encoded certificate with X.509 binary data
     * @param string $x5c
     * @return string
     */
    protected function _createCertificatePem(string $x5c): string
    {
        $pem = '-----BEGIN CERTIFICATE-----' . "\n";
        $pem .= \chunk_split(\base64_encode($x5c), 64, "\n");
        $pem .= '-----END CERTIFICATE-----' . "\n";
        return $pem;
    }

    /**
     * creates a PEM encoded chain file
     * @return string|null
     */
    protected function _createX5cChainFile(): ?string
    {
        $content = '';
        if (count($this->_x5c_chain) > 0) {
            foreach ($this->_x5c_chain as $x5c) {
                $certInfo = \openssl_x509_parse($this->_createCertificatePem($x5c));

                // check if certificate is self-signed
                if (\is_array($certInfo) && \is_array($certInfo['issuer']) && \is_array($certInfo['subject'])) {
                    $selfSigned = false;

                    $subjectKeyIdentifier = $certInfo['extensions']['subjectKeyIdentifier'] ?? null;
                    $authorityKeyIdentifier = $certInfo['extensions']['authorityKeyIdentifier'] ?? null;

                    if ($authorityKeyIdentifier && str_starts_with($authorityKeyIdentifier, 'keyid:')) {
                        $authorityKeyIdentifier = substr($authorityKeyIdentifier, 6);
                    }
                    if ($subjectKeyIdentifier && str_starts_with($subjectKeyIdentifier, 'keyid:')) {
                        $subjectKeyIdentifier = substr($subjectKeyIdentifier, 6);
                    }

                    if (($subjectKeyIdentifier && !$authorityKeyIdentifier) || ($authorityKeyIdentifier && $authorityKeyIdentifier === $subjectKeyIdentifier)) {
                        $selfSigned = true;
                    }

                    if (!$selfSigned) {
                        $content .= "\n" . $this->_createCertificatePem($x5c) . "\n";
                    }
                }
            }
        }

        if ($content) {
            $this->_x5c_tempFile = \tempnam(\sys_get_temp_dir(), 'x5c_');
            if (\file_put_contents($this->_x5c_tempFile, $content) !== false) {
                return $this->_x5c_tempFile;
            }
        }

        return null;
    }


    /**
     * returns the name and openssl key for provided cose number.
     * @param int $coseNumber
     * @return stdClass|null
     */
    protected function _getCoseAlgorithm(int $coseNumber): ?stdClass
    {
        // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
        $coseAlgorithms = array(
            array(
                'hash' => 'SHA1',
                'openssl' => OPENSSL_ALGO_SHA1,
                'cose' => array(
                    -65535  // RS1
                )),

            array(
                'hash' => 'SHA256',
                'openssl' => OPENSSL_ALGO_SHA256,
                'cose' => array(
                    -257, // RS256
                    -37,  // PS256
                    -7,   // ES256
                    5     // HMAC256
                )),

            array(
                'hash' => 'SHA384',
                'openssl' => OPENSSL_ALGO_SHA384,
                'cose' => array(
                    -258, // RS384
                    -38,  // PS384
                    -35,  // ES384
                    6     // HMAC384
                )),

            array(
                'hash' => 'SHA512',
                'openssl' => OPENSSL_ALGO_SHA512,
                'cose' => array(
                    -259, // RS512
                    -39,  // PS512
                    -36,  // ES512
                    7     // HMAC512
                ))
        );

        foreach ($coseAlgorithms as $coseAlgorithm) {
            if (\in_array($coseNumber, $coseAlgorithm['cose'], true)) {
                $return = new stdClass();
                $return->hash = $coseAlgorithm['hash'];
                $return->openssl = $coseAlgorithm['openssl'];
                return $return;
            }
        }

        return null;
    }
}