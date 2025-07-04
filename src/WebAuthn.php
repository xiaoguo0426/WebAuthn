<?php

namespace Onetech\WebAuthn;

use Onetech\WebAuthn\Binary\ByteBuffer;
use Random\RandomException;
use SodiumException;
use stdClass;

/**
 * WebAuthn
 * @author Lukas Buchs
 * @license https://github.com/lbuchs/WebAuthn/blob/master/LICENSE MIT
 */
class WebAuthn
{
    private string $_rpName;
    private string $_rpId;
    private string $_rpIdHash;
    private $_challenge;
    private ?int $_signatureCounter = null;
    private $_caFiles;
    private $_formats;
    private $_androidKeyHashes;

    /**
     * Initialize a new WebAuthn server
     * @param string $rpName the relying on party name
     * @param string $rpId the relying on party ID = the domain name
     * @param bool $useBase64UrlEncoding true to use base64 url encoding for binary data in json objects. Default is a RFC 1342-Like serialized string.
     * @throws WebAuthnException
     */
    public function __construct(string $rpName, string $rpId, $allowedFormats = null, bool $useBase64UrlEncoding = false)
    {
        $this->_rpName = $rpName;
        $this->_rpId = $rpId;
        $this->_rpIdHash = \hash('sha256', $rpId, true);
        ByteBuffer::$useBase64UrlEncoding = !!$useBase64UrlEncoding;
        $supportedFormats = array('android-key', 'android-safetynet', 'apple', 'fido-u2f', 'none', 'packed', 'tpm');

        if (!\function_exists('\openssl_open')) {
            throw new WebAuthnException('OpenSSL-Module not installed');
        }

        if (!\in_array('SHA256', \array_map('\strtoupper', \openssl_get_md_methods()))) {
            throw new WebAuthnException('SHA256 not supported by this openssl installation.');
        }

        // default: all format
        if (!is_array($allowedFormats)) {
            $allowedFormats = $supportedFormats;
        }
        $this->_formats = $allowedFormats;

        // validate formats
        $invalidFormats = \array_diff($this->_formats, $supportedFormats);
        if (!$this->_formats || $invalidFormats) {
            throw new WebAuthnException('invalid formats on construct: ' . implode(', ', $invalidFormats));
        }
    }

    /**
     * add a root certificate to verify new registrations
     * @param string $path file path of / directory with root certificates
     * @param array|null $certFileExtensions if adding a direction, all files with provided extension are added. default: pem, crt, cer, der
     */
    public function addRootCertificates(string $path, ?array $certFileExtensions = null): void
    {
        if (!\is_array($this->_caFiles)) {
            $this->_caFiles = [];
        }
        if ($certFileExtensions === null) {
            $certFileExtensions = array('pem', 'crt', 'cer', 'der');
        }
        $path = \rtrim(\trim($path), '\\/');
        if (\is_dir($path)) {
            foreach (\scandir($path) as $ca) {
                if (\is_file($path . DIRECTORY_SEPARATOR . $ca) && \in_array(\strtolower(\pathinfo($ca, PATHINFO_EXTENSION)), $certFileExtensions)) {
                    $this->addRootCertificates($path . DIRECTORY_SEPARATOR . $ca);
                }
            }
        } else if (\is_file($path) && !\in_array(\realpath($path), $this->_caFiles)) {
            $this->_caFiles[] = \realpath($path);
        }
    }

    /**
     * add key hashes for android verification
     * @param string[] $hashes
     * @return void
     */
    public function addAndroidKeyHashes(array $hashes): void
    {
        if (!\is_array($this->_androidKeyHashes)) {
            $this->_androidKeyHashes = [];
        }

        foreach ($hashes as $hash) {
            if (is_string($hash)) {
                $this->_androidKeyHashes[] = $hash;
            }
        }
    }

    /**
     * Returns the generated challenge to save for later validation
     * @return ByteBuffer
     */
    public function getChallenge(): ByteBuffer
    {
        return $this->_challenge;
    }

    /**
     * generates the object for a key registration
     * provide this data to navigator.credentials.create
     * @param string $userId
     * @param string $userName
     * @param string $userDisplayName
     * @param int $timeout timeout in seconds
     * @param bool|string $requireResidentKey 'required', if the key should be stored by the authentication device
     *                                             Valid values:
     *                                             true = required
     *                                             false = preferred
     *                                             string 'required' 'preferred' 'discouraged'
     * @param bool|string $requireUserVerification indicates that you require user verification and will fail the operation
     *                                             if the response does not have the UV flag set.
     *                                             Valid values:
     *                                             true = required
     *                                             false = preferred
     *                                             string 'required' 'preferred' 'discouraged'
     * @param null $crossPlatformAttachment true for cross-platform devices (eg. fido usb),
     *                                             false for platform devices (e.g. windows hello, android safetynet),
     *                                             null for both
     * @param array $excludeCredentialIds an array of ids, which are already registered, to prevent re-registration
     * @return stdClass
     * @throws WebAuthnException|RandomException
     */
    public function getCreateArgs(string $userId, string $userName, string $userDisplayName, int $timeout = 20, bool|string $requireResidentKey = false, bool|string $requireUserVerification = false, $crossPlatformAttachment = null, array $excludeCredentialIds = []): stdClass
    {

        $args = new stdClass();
        $args->publicKey = new stdClass();

        // relying on party
        $args->publicKey->rp = new stdClass();
        $args->publicKey->rp->name = $this->_rpName;
        $args->publicKey->rp->id = $this->_rpId;

        $args->publicKey->authenticatorSelection = new stdClass();
        $args->publicKey->authenticatorSelection->userVerification = 'preferred';

        // validate User Verification Requirement
        if (\is_bool($requireUserVerification)) {
            $args->publicKey->authenticatorSelection->userVerification = $requireUserVerification ? 'required' : 'preferred';

        } else if (\is_string($requireUserVerification) && \in_array(\strtolower($requireUserVerification), ['required', 'preferred', 'discouraged'])) {
            $args->publicKey->authenticatorSelection->userVerification = \strtolower($requireUserVerification);
        }

        // validate Resident Key Requirement
        if (\is_bool($requireResidentKey) && $requireResidentKey) {
            $args->publicKey->authenticatorSelection->requireResidentKey = true;
            $args->publicKey->authenticatorSelection->residentKey = 'required';

        } else if (\is_string($requireResidentKey) && \in_array(\strtolower($requireResidentKey), ['required', 'preferred', 'discouraged'])) {
            $requireResidentKey = \strtolower($requireResidentKey);
            $args->publicKey->authenticatorSelection->residentKey = $requireResidentKey;
            $args->publicKey->authenticatorSelection->requireResidentKey = $requireResidentKey === 'required';
        }

        // filter authenticators attached with the specified authenticator attachment modality
        if (\is_bool($crossPlatformAttachment)) {
            $args->publicKey->authenticatorSelection->authenticatorAttachment = $crossPlatformAttachment ? 'cross-platform' : 'platform';
        }

        // user
        $args->publicKey->user = new stdClass();
        $args->publicKey->user->id = new ByteBuffer($userId); // binary
        $args->publicKey->user->name = $userName;
        $args->publicKey->user->displayName = $userDisplayName;

        // supported algorithms
        $args->publicKey->pubKeyCredParams = [];

        if (function_exists('sodium_crypto_sign_verify_detached') || \in_array('ed25519', \openssl_get_curve_names(), true)) {
            $tmp = new stdClass();
            $tmp->type = 'public-key';
            $tmp->alg = -8; // EdDSA
            $args->publicKey->pubKeyCredParams[] = $tmp;
            unset ($tmp);
        }

        if (\in_array('prime256v1', \openssl_get_curve_names(), true)) {
            $tmp = new stdClass();
            $tmp->type = 'public-key';
            $tmp->alg = -7; // ES256
            $args->publicKey->pubKeyCredParams[] = $tmp;
            unset ($tmp);
        }

        $tmp = new stdClass();
        $tmp->type = 'public-key';
        $tmp->alg = -257; // RS256
        $args->publicKey->pubKeyCredParams[] = $tmp;
        unset ($tmp);

        // if there are root certificates added, we need direct attestation to validate
        // against the root certificate. If there are no root-certificates added,
        // anonymization ca are also accepted, because we can't validate the root anyway.
        $attestation = 'indirect';
        if (\is_array($this->_caFiles)) {
            $attestation = 'direct';
        }

        $args->publicKey->attestation = \count($this->_formats) === 1 && \in_array('none', $this->_formats) ? 'none' : $attestation;
        $args->publicKey->extensions = new stdClass();
        $args->publicKey->extensions->exts = true;
        $args->publicKey->timeout = $timeout * 1000; // microseconds
        $args->publicKey->challenge = $this->_createChallenge(); // binary

        //prevent re-registration by specifying existing credentials
        $args->publicKey->excludeCredentials = [];

        if (is_array($excludeCredentialIds)) {
            foreach ($excludeCredentialIds as $id) {
                $tmp = new stdClass();
                $tmp->id = $id instanceof ByteBuffer ? $id : new ByteBuffer($id);  // binary
                $tmp->type = 'public-key';
                $tmp->transports = array('usb', 'nfc', 'ble', 'hybrid', 'internal');
                $args->publicKey->excludeCredentials[] = $tmp;
                unset ($tmp);
            }
        }

        return $args;
    }

    /**
     * generates the object for key validation
     * Provide this data to navigator.credentials.get
     * @param array $credentialIds binary
     * @param int $timeout timeout in seconds
     * @param bool $allowUsb allow removable USB
     * @param bool $allowNfc allow Near Field Communication (NFC)
     * @param bool $allowBle allow Bluetooth
     * @param bool $allowHybrid allow a combination of (often separate) data-transport and proximity mechanisms.
     * @param bool $allowInternal allow client device-specific transport. These authenticators are not removable from the client device.
     * @param bool|string $requireUserVerification indicates that you require user verification and will fail the operation
     *                                             if the response does not have the UV flag set.
     *                                             Valid values:
     *                                             true = required
     *                                             false = preferred
     *                                             string 'required' 'preferred' 'discouraged'
     * @return stdClass
     * @throws WebAuthnException|RandomException
     */
    public function getGetArgs(array $credentialIds = [], int $timeout = 20, bool $allowUsb = true, bool $allowNfc = true, bool $allowBle = true, bool $allowHybrid = true, bool $allowInternal = true, bool|string $requireUserVerification = false): stdClass
    {

        // validate User Verification Requirement
        if (\is_bool($requireUserVerification)) {
            $requireUserVerification = $requireUserVerification ? 'required' : 'preferred';
        } else if (\is_string($requireUserVerification) && \in_array(\strtolower($requireUserVerification), ['required', 'preferred', 'discouraged'])) {
            $requireUserVerification = \strtolower($requireUserVerification);
        } else {
            $requireUserVerification = 'preferred';
        }

        $args = new stdClass();
        $args->publicKey = new stdClass();
        $args->publicKey->timeout = $timeout * 1000; // microseconds
        $args->publicKey->challenge = $this->_createChallenge();  // binary
        $args->publicKey->userVerification = $requireUserVerification;
        $args->publicKey->rpId = $this->_rpId;

        if (\is_array($credentialIds) && \count($credentialIds) > 0) {
            $args->publicKey->allowCredentials = [];

            foreach ($credentialIds as $id) {
                $tmp = new stdClass();
                $tmp->id = $id instanceof ByteBuffer ? $id : new ByteBuffer($id);  // binary
                $tmp->transports = [];

                if ($allowUsb) {
                    $tmp->transports[] = 'usb';
                }
                if ($allowNfc) {
                    $tmp->transports[] = 'nfc';
                }
                if ($allowBle) {
                    $tmp->transports[] = 'ble';
                }
                if ($allowHybrid) {
                    $tmp->transports[] = 'hybrid';
                }
                if ($allowInternal) {
                    $tmp->transports[] = 'internal';
                }

                $tmp->type = 'public-key';
                $args->publicKey->allowCredentials[] = $tmp;
                unset ($tmp);
            }
        }

        return $args;
    }

    /**
     * returns the new signature counter value.
     * returns null if there is no counter
     * @return ?int
     */
    public function getSignatureCounter(): ?int
    {
        return \is_int($this->_signatureCounter) ? $this->_signatureCounter : null;
    }

    /**
     * process a create request and returns data to save for future logins
     * @param string $clientDataJSON binary from browser
     * @param string $attestationObject binary from browser
     * @param string|ByteBuffer $challenge binary used challenge
     * @param bool $requireUserVerification true, if the device must verify user (e.g. by biometric data or pin)
     * @param bool $requireUserPresent false, if the device must NOT check user presence (e.g. by pressing a button)
     * @param bool $failIfRootMismatch false, if there should be no error thrown if root certificate doesn't match
     * @param bool $requireCtsProfileMatch false, if you don't want to check if the device is approved as a Google-certified Android device.
     * @return stdClass
     * @throws WebAuthnException
     */
    public function processCreate(string $clientDataJSON, string $attestationObject, ByteBuffer|string $challenge, bool $requireUserVerification = false, bool $requireUserPresent = true, bool $failIfRootMismatch = true, bool $requireCtsProfileMatch = true): stdClass
    {
        $clientDataHash = \hash('sha256', $clientDataJSON, true);
        $clientData = \json_decode($clientDataJSON);
        $challenge = $challenge instanceof ByteBuffer ? $challenge : new ByteBuffer($challenge);

        // security: https://www.w3.org/TR/webauthn/#registering-a-new-credential

        // 2. Let C, the client data claimed as collected during the credential creation,
        //    be the result of running an implementation-specific JSON parser on JSON text.
        if (!\is_object($clientData)) {
            throw new WebAuthnException('invalid client data', WebAuthnException::INVALID_DATA);
        }

        // 3. Verify that the value of C.type is webauthn.create.
        if (!\property_exists($clientData, 'type') || $clientData->type !== 'webauthn.create') {
            throw new WebAuthnException('invalid type', WebAuthnException::INVALID_TYPE);
        }

        // 4. Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the create() call.
        if (!\property_exists($clientData, 'challenge') || ByteBuffer::fromBase64Url($clientData->challenge)->getBinaryString() !== $challenge->getBinaryString()) {
            throw new WebAuthnException('invalid challenge', WebAuthnException::INVALID_CHALLENGE);
        }

        // 5. Verify that the value of C.origin matches the Relying on Party's origin.
        if (!\property_exists($clientData, 'origin') || !$this->_checkOrigin($clientData->origin)) {
            throw new WebAuthnException('invalid origin', WebAuthnException::INVALID_ORIGIN);
        }

        // Attestation
        $attestationObject = new Attestation\AttestationObject($attestationObject, $this->_formats);

        // 9. Verify that the RP ID hash in authData is indeed the SHA-256 hash of the RP ID expected by the RP.
        if (!$attestationObject->validateRpIdHash($this->_rpIdHash)) {
            throw new WebAuthnException('invalid rpId hash', WebAuthnException::INVALID_RELYING_PARTY);
        }

        // 14. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature
        if (!$attestationObject->validateAttestation($clientDataHash)) {
            throw new WebAuthnException('invalid certificate signature', WebAuthnException::INVALID_SIGNATURE);
        }

        // Android-SafetyNet: if required, check for Compatibility Testing Suite (CTS).
        if ($requireCtsProfileMatch && $attestationObject->getAttestationFormat() instanceof Attestation\Format\AndroidSafetyNet) {
            if (!$attestationObject->getAttestationFormat()->ctsProfileMatch()) {
                throw new WebAuthnException('invalid ctsProfileMatch: device is not approved as a Google-certified Android device.', WebAuthnException::ANDROID_NOT_TRUSTED);
            }
        }

        // 15. If validation is successful, obtain a list of acceptable trust anchors
        $rootValid = is_array($this->_caFiles) ? $attestationObject->validateRootCertificate($this->_caFiles) : null;
        if ($failIfRootMismatch && is_array($this->_caFiles) && !$rootValid) {
            throw new WebAuthnException('invalid root certificate', WebAuthnException::CERTIFICATE_NOT_TRUSTED);
        }

        // 10. Verify that the User Present bit of the flags in authData is set.
        $userPresent = $attestationObject->getAuthenticatorData()->getUserPresent();
        if ($requireUserPresent && !$userPresent) {
            throw new WebAuthnException('user not present during authentication', WebAuthnException::USER_PRESENT);
        }

        // 11. If user verification is required for this registration, verify that the User Verified A bit of the flags in authData is set.
        $userVerified = $attestationObject->getAuthenticatorData()->getUserVerified();
        if ($requireUserVerification && !$userVerified) {
            throw new WebAuthnException('user not verified during authentication', WebAuthnException::USER_VERIFICATED);
        }

        $signCount = $attestationObject->getAuthenticatorData()->getSignCount();
        if ($signCount > 0) {
            $this->_signatureCounter = $signCount;
        }

        // prepare data to store for future logins
        $data = new stdClass();
        $data->rpId = $this->_rpId;
        $data->attestationFormat = $attestationObject->getAttestationFormatName();
        $data->credentialId = $attestationObject->getAuthenticatorData()->getCredentialId();
        $data->credentialPublicKey = $attestationObject->getAuthenticatorData()->getPublicKeyPem();
        $data->certificateChain = $attestationObject->getCertificateChain();
        $data->certificate = $attestationObject->getCertificatePem();
        $data->certificateIssuer = $attestationObject->getCertificateIssuer();
        $data->certificateSubject = $attestationObject->getCertificateSubject();
        $data->signatureCounter = $this->_signatureCounter;
        $data->AAGUID = $attestationObject->getAuthenticatorData()->getAAGUID();
        $data->rootValid = $rootValid;
        $data->userPresent = $userPresent;
        $data->userVerified = $userVerified;
        $data->isBackupEligible = $attestationObject->getAuthenticatorData()->getIsBackupEligible();
        $data->isBackedUp = $attestationObject->getAuthenticatorData()->getIsBackup();
        return $data;
    }


    /**
     * process a get request
     * @param string $clientDataJSON binary from browser
     * @param string $authenticatorData binary from browser
     * @param string $signature binary from browser
     * @param string $credentialPublicKey string PEM-formated public key from used credentialId
     * @param string|ByteBuffer $challenge binary from used challenge
     * @param int|null $prevSignatureCnt signature count value of the last login
     * @param bool $requireUserVerification true, if the device must verify user (e.g. by biometric data or pin)
     * @param bool $requireUserPresent true, if the device must check user presence (e.g. by pressing a button)
     * @return boolean true if get is successful
     * @throws WebAuthnException|SodiumException
     */
    public function processGet(string $clientDataJSON, string $authenticatorData, string $signature, string $credentialPublicKey, string|ByteBuffer $challenge, ?int $prevSignatureCnt = null, bool $requireUserVerification = false, bool $requireUserPresent = true): bool
    {
        $authenticatorObj = new Attestation\AuthenticatorData($authenticatorData);
        $clientDataHash = \hash('sha256', $clientDataJSON, true);
        $clientData = \json_decode($clientDataJSON);
        $challenge = $challenge instanceof ByteBuffer ? $challenge : new ByteBuffer($challenge);

        // https://www.w3.org/TR/webauthn/#verifying-assertion

        // 1. If the allowCredentials option was given when this authentication ceremony was initiated,
        //    verify that credential.id identifies one of the public key credentials that were listed in allowCredentials.
        //    -> TO BE VERIFIED BY IMPLEMENTATION

        // 2. If credential.response.userHandle is present, verify that the user identified
        //    by this value is the owner of the public key credential identified by credential.id.
        //    -> TO BE VERIFIED BY IMPLEMENTATION

        // 3. Using credential’s id attribute (or the corresponding rawId, if base64url encoding is
        //    inappropriate for your use case), look up the corresponding credential public key.
        //    -> TO BE LOOKED UP BY IMPLEMENTATION

        // 5. Let JSON text be the result of running UTF-8 decode on the value of cData.
        if (!\is_object($clientData)) {
            throw new WebAuthnException('invalid client data', WebAuthnException::INVALID_DATA);
        }

        // 7. Verify that the value of C.type is the string webauthn.get.
        if (!\property_exists($clientData, 'type') || $clientData->type !== 'webauthn.get') {
            throw new WebAuthnException('invalid type', WebAuthnException::INVALID_TYPE);
        }

        // 8. Verify that the value of C.challenge matches the challenge that was sent to the
        //    authenticator in the PublicKeyCredentialRequestOptions passed to the get() call.
        if (!\property_exists($clientData, 'challenge') || ByteBuffer::fromBase64Url($clientData->challenge)->getBinaryString() !== $challenge->getBinaryString()) {
            throw new WebAuthnException('invalid challenge', WebAuthnException::INVALID_CHALLENGE);
        }

        // 9. Verify that the value of C.origin matches the Relying on Party's origin.
        if (!\property_exists($clientData, 'origin') || !$this->_checkOrigin($clientData->origin)) {
            throw new WebAuthnException('invalid origin', WebAuthnException::INVALID_ORIGIN);
        }

        // 11. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying on Party.
        if ($authenticatorObj->getRpIdHash() !== $this->_rpIdHash) {
            throw new WebAuthnException('invalid rpId hash', WebAuthnException::INVALID_RELYING_PARTY);
        }

        // 12. Verify that the User Present bit of the flags in authData is set
        if ($requireUserPresent && !$authenticatorObj->getUserPresent()) {
            throw new WebAuthnException('user not present during authentication', WebAuthnException::USER_PRESENT);
        }

        // 13. If user verification is required for this assertion, verify that the User Verified A bit of the flags in authData is set.
        if ($requireUserVerification && !$authenticatorObj->getUserVerified()) {
            throw new WebAuthnException('user not verification during authentication', WebAuthnException::USER_VERIFICATED);
        }

        // 14. Verify the values of the client extension outputs
        //     (extensions not implemented)

        // 16. Using the credential public key looked up in step 3, verify that sig is a valid signature
        //     over the binary concatenation of authData and hash.
        $dataToVerify = $authenticatorData;
        $dataToVerify .= $clientDataHash;

        if (!$this->_verifySignature($dataToVerify, $signature, $credentialPublicKey)) {
            throw new WebAuthnException('invalid signature', WebAuthnException::INVALID_SIGNATURE);
        }

        $signatureCounter = $authenticatorObj->getSignCount();
        if ($signatureCounter !== 0) {
            $this->_signatureCounter = $signatureCounter;
        }

        // 17. If either of the signature counter value authData.signCount or
        //     previous signature count is nonzero, and if authData.signCount
        //     less than or equal to previous signature count, it's a signal
        //     that the authenticator may be cloned
        if ($prevSignatureCnt !== null) {
            if ($signatureCounter !== 0 || $prevSignatureCnt !== 0) {
                if ($prevSignatureCnt >= $signatureCounter) {
                    throw new WebAuthnException('signature counter not valid', WebAuthnException::SIGNATURE_COUNTER);
                }
            }
        }

        return true;
    }

    /**
     * Downloads root certificates from FIDO Alliance Metadata Service (MDS) to a specific folder
     * https://fidoalliance.org/metadata/
     * @param string $certFolder Folder path to save the certificates in PEM format.
     * @param bool $deleteCerts delete certificates in the target folder before adding the new ones.
     * @return int number of certificates
     * @throws WebAuthnException
     */
    public function queryFidoMetaDataService(string $certFolder, bool $deleteCerts = true): int
    {
        $url = 'https://mds.fidoalliance.org/';
        $raw = null;
        if (\function_exists('curl_init')) {
            $ch = \curl_init($url);
            \curl_setopt($ch, CURLOPT_HEADER, false);
            \curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            \curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            \curl_setopt($ch, CURLOPT_USERAGENT, 'github.com/lbuchs/WebAuthn - A simple PHP WebAuthn server library');
            $raw = \curl_exec($ch);
            \curl_close($ch);
        } else {
            $raw = \file_get_contents($url);
        }

        $certFolder = \rtrim(\realpath($certFolder), '\\/');
        if (!is_dir($certFolder)) {
            throw new WebAuthnException('Invalid folder path for query FIDO Alliance Metadata Service');
        }

        if (!\is_string($raw)) {
            throw new WebAuthnException('Unable to query FIDO Alliance Metadata Service');
        }

        $jwt = \explode('.', $raw);
        if (\count($jwt) !== 3) {
            throw new WebAuthnException('Invalid JWT from FIDO Alliance Metadata Service');
        }

        if ($deleteCerts) {
            foreach (\scandir($certFolder) as $ca) {
                if (str_ends_with($ca, '.pem')) {
                    if (\unlink($certFolder . DIRECTORY_SEPARATOR . $ca) === false) {
                        throw new WebAuthnException('Cannot delete certs in folder for FIDO Alliance Metadata Service');
                    }
                }
            }
        }

        list($header, $payload, $hash) = $jwt;
        $payload = Binary\ByteBuffer::fromBase64Url($payload)->getJson();

        $count = 0;
        if (\is_object($payload) && \property_exists($payload, 'entries') && \is_array($payload->entries)) {
            foreach ($payload->entries as $entry) {
                if (\is_object($entry) && \property_exists($entry, 'metadataStatement') && \is_object($entry->metadataStatement)) {
                    $description = $entry->metadataStatement->description ?? null;
                    $attestationRootCertificates = $entry->metadataStatement->attestationRootCertificates ?? null;

                    if ($description && $attestationRootCertificates) {

                        // create filename
                        $certFilename = \preg_replace('/[^a-z0-9]/i', '_', $description);
                        $certFilename = \trim(\preg_replace('/_{2,}/i', '_', $certFilename), '_') . '.pem';
                        $certFilename = \strtolower($certFilename);

                        // add certificate
                        $certContent = $description . "\n";
                        $certContent .= \str_repeat('-', \mb_strlen($description)) . "\n";

                        foreach ($attestationRootCertificates as $attestationRootCertificate) {
                            $attestationRootCertificate = \str_replace(["\n", "\r", ' '], '', \trim($attestationRootCertificate));
                            $count++;
                            $certContent .= "\n-----BEGIN CERTIFICATE-----\n";
                            $certContent .= \chunk_split($attestationRootCertificate, 64, "\n");
                            $certContent .= "-----END CERTIFICATE-----\n";
                        }

                        if (\file_put_contents($certFolder . DIRECTORY_SEPARATOR . $certFilename, $certContent) === false) {
                            throw new WebAuthnException('unable to save certificate from FIDO Alliance Metadata Service');
                        }
                    }
                }
            }
        }

        return $count;
    }

    // -----------------------------------------------
    // PRIVATE
    // -----------------------------------------------

    /**
     * checks if the origin matches the RP ID
     * @param string $origin
     * @return boolean
     */
    private function _checkOrigin(string $origin): bool
    {
        if (str_starts_with($origin, 'android:apk-key-hash:')) {
            return $this->_checkAndroidKeyHashes($origin);
        }

        // https://www.w3.org/TR/webauthn/#rp-id

        // The origin's scheme must be https
        if ($this->_rpId !== 'localhost' && \parse_url($origin, PHP_URL_SCHEME) !== 'https') {
            return false;
        }

        // extract host from origin
        $host = \parse_url($origin, PHP_URL_HOST);
        $host = \trim($host, '.');

        // The RP ID must be equal to the origin's effective domain, or a registrable
        // domain suffix of the origin's effective domain.
        return \preg_match('/' . \preg_quote($this->_rpId) . '$/i', $host) === 1;
    }

    /**
     * checks if the origin value contains a known android key hash
     * @param string $origin
     * @return boolean
     */
    private function _checkAndroidKeyHashes(string $origin): bool
    {
        $parts = explode('android:apk-key-hash:', $origin);
        if (count($parts) !== 2) {
            return false;
        }
        return in_array($parts[1], $this->_androidKeyHashes, true);
    }

    /**
     * generates a new challenge
     * @param int $length
     * @return ByteBuffer
     * @throws WebAuthnException
     * @throws RandomException
     */
    private function _createChallenge(int $length = 32): ByteBuffer
    {
        if (!$this->_challenge) {
            $this->_challenge = ByteBuffer::randomBuffer($length);
        }
        return $this->_challenge;
    }

    /**
     * check if the signature is valid.
     * @param string $dataToVerify
     * @param string $signature
     * @param string $credentialPublicKey
     * @return bool
     * @throws WebAuthnException
     * @throws SodiumException
     */
    private function _verifySignature(string $dataToVerify, string $signature, string $credentialPublicKey): bool
    {

        // Use Sodium to verify EdDSA 25519 as It's not yet supported by openssl
        if (\function_exists('sodium_crypto_sign_verify_detached') && !\in_array('ed25519', \openssl_get_curve_names(), true)) {
            $pkParts = [];
            if (\preg_match('/BEGIN PUBLIC KEY-+(?:\s|\n|\r)+([^\-]+)(?:\s|\n|\r)*-+END PUBLIC KEY/i', $credentialPublicKey, $pkParts)) {
                $rawPk = \base64_decode($pkParts[1]);

                // 30        = der sequence
                // 2a        = length 42 byte
                // 30        = der sequence
                // 05        = length 5 byte
                // 06        = der OID
                // 03        = OID length 3 byte
                // 2b 65 70  = OID 1.3.101.112 curveEd25519 (EdDSA 25519 signature algorithm)
                // 03        = der bit string
                // 21        = length 33 byte
                // 00        = null padding
                // [...]     = 32 byte x-curve
                $okpPrefix = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";

                if ($rawPk && \strlen($rawPk) === 44 && str_starts_with($rawPk, $okpPrefix)) {
                    $publicKeyXCurve = \substr($rawPk, \strlen($okpPrefix));
                    return \sodium_crypto_sign_verify_detached($signature, $dataToVerify, $publicKeyXCurve);
                }
            }
        }

        // verify with openSSL
        $publicKey = \openssl_pkey_get_public($credentialPublicKey);
        if ($publicKey === false) {
            throw new WebAuthnException('public key invalid', WebAuthnException::INVALID_PUBLIC_KEY);
        }

        return \openssl_verify($dataToVerify, $signature, $publicKey, OPENSSL_ALGO_SHA256) === 1;
    }
}
