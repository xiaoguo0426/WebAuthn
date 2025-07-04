<?php


namespace Onetech\WebAuthn\Binary;

use Onetech\WebAuthn\WebAuthnException;
use Random\RandomException;

/**
 * Modified version of https://github.com/madwizard-thomas/webauthn-server/blob/master/src/Format/ByteBuffer.php
 * Copyright © 2018 Thomas Bleeker - MIT licensed
 * Modified by Lukas Buchs
 * Thanks Thomas for your work!
 */
class ByteBuffer implements \JsonSerializable, \Serializable
{
    /**
     * @var bool
     */
    public static bool $useBase64UrlEncoding = false;

    /**
     * @var string
     */
    private string $_data;

    /**
     * @var int
     */
    private int $_length;

    public function __construct($binaryData)
    {
        $this->_data = (string)$binaryData;
        $this->_length = \strlen($binaryData);
    }


    // -----------------------
    // PUBLIC STATIC
    // -----------------------

    /**
     * create a ByteBuffer from a base64 url encoded string
     * @param $base64url
     * @return ByteBuffer
     * @throws WebAuthnException
     */
    public static function fromBase64Url($base64url): ByteBuffer
    {
        $bin = self::_base64url_decode($base64url);
        if ($bin === false) {
            throw new WebAuthnException('ByteBuffer: Invalid base64 url string', WebAuthnException::BYTEBUFFER);
        }
        return new ByteBuffer($bin);
    }

    /**
     * create a ByteBuffer from a base64 url encoded string
     * @param $hex
     * @return ByteBuffer
     * @throws WebAuthnException
     */
    public static function fromHex($hex): ByteBuffer
    {
        $bin = \hex2bin($hex);
        if ($bin === false) {
            throw new WebAuthnException('ByteBuffer: Invalid hex string', WebAuthnException::BYTEBUFFER);
        }
        return new ByteBuffer($bin);
    }

    /**
     * create a random ByteBuffer
     * @param $length
     * @return ByteBuffer
     * @throws WebAuthnException
     * @throws RandomException
     */
    public static function randomBuffer($length): ByteBuffer
    {
        if (\function_exists('random_bytes')) { // >PHP 7.0
            return new ByteBuffer(\random_bytes($length));

        } else if (\function_exists('openssl_random_pseudo_bytes')) {
            return new ByteBuffer(\openssl_random_pseudo_bytes($length));

        } else {
            throw new WebAuthnException('ByteBuffer: cannot generate random bytes', WebAuthnException::BYTEBUFFER);
        }
    }

    // -----------------------
    // PUBLIC
    // -----------------------

    /**
     * @throws WebAuthnException
     */
    public function getBytes($offset, $length): string
    {
        if ($offset < 0 || $length < 0 || ($offset + $length > $this->_length)) {
            throw new WebAuthnException('ByteBuffer: Invalid offset or length', WebAuthnException::BYTEBUFFER);
        }
        return \substr($this->_data, $offset, $length);
    }

    /**
     * @throws WebAuthnException
     */
    public function getByteVal($offset): int
    {
        if ($offset < 0 || $offset >= $this->_length) {
            throw new WebAuthnException('ByteBuffer: Invalid offset', WebAuthnException::BYTEBUFFER);
        }
        return \ord(\substr($this->_data, $offset, 1));
    }

    /**
     * @throws WebAuthnException
     */
    public function getJson($jsonFlags = 0)
    {
        $data = \json_decode($this->getBinaryString(), null, 512, $jsonFlags);
        if (\json_last_error() !== JSON_ERROR_NONE) {
            throw new WebAuthnException(\json_last_error_msg(), WebAuthnException::BYTEBUFFER);
        }
        return $data;
    }

    /**
     * @return int
     */
    public function getLength(): int
    {
        return $this->_length;
    }

    /**
     * @param $offset
     * @return mixed
     * @throws WebAuthnException
     */
    public function getUint16Val($offset): mixed
    {
        if ($offset < 0 || ($offset + 2) > $this->_length) {
            throw new WebAuthnException('ByteBuffer: Invalid offset', WebAuthnException::BYTEBUFFER);
        }
        return unpack('n', $this->_data, $offset)[1];
    }

    /**
     * @param $offset
     * @return mixed
     * @throws WebAuthnException
     */
    public function getUint32Val($offset): mixed
    {
        if ($offset < 0 || ($offset + 4) > $this->_length) {
            throw new WebAuthnException('ByteBuffer: Invalid offset', WebAuthnException::BYTEBUFFER);
        }
        $val = unpack('N', $this->_data, $offset)[1];

        // Signed integer overflow causes signed negative numbers
        if ($val < 0) {
            throw new WebAuthnException('ByteBuffer: Value out of integer range.', WebAuthnException::BYTEBUFFER);
        }
        return $val;
    }

    /**
     * @param $offset
     * @return mixed
     * @throws WebAuthnException
     */
    public function getUint64Val($offset): mixed
    {
        if (PHP_INT_SIZE < 8) {
            throw new WebAuthnException('ByteBuffer: 64-bit values not supported by this system', WebAuthnException::BYTEBUFFER);
        }
        if ($offset < 0 || ($offset + 8) > $this->_length) {
            throw new WebAuthnException('ByteBuffer: Invalid offset', WebAuthnException::BYTEBUFFER);
        }
        $val = unpack('J', $this->_data, $offset)[1];

        // Signed integer overflow causes signed negative numbers
        if ($val < 0) {
            throw new WebAuthnException('ByteBuffer: Value out of integer range.', WebAuthnException::BYTEBUFFER);
        }

        return $val;
    }

    /**
     * @param $offset
     * @return float|int
     * @throws WebAuthnException
     */
    public function getHalfFloatVal($offset)
    {
        //FROM spec pseudo decode_half(unsigned char *halfp)
        $half = $this->getUint16Val($offset);

        $exp = ($half >> 10) & 0x1f;
        $mant = $half & 0x3ff;

        if ($exp === 0) {
            $val = $mant * (2 ** -24);
        } elseif ($exp !== 31) {
            $val = ($mant + 1024) * (2 ** ($exp - 25));
        } else {
            $val = ($mant === 0) ? INF : NAN;
        }

        return ($half & 0x8000) ? -$val : $val;
    }

    /**
     * @throws WebAuthnException
     */
    public function getFloatVal($offset)
    {
        if ($offset < 0 || ($offset + 4) > $this->_length) {
            throw new WebAuthnException('ByteBuffer: Invalid offset', WebAuthnException::BYTEBUFFER);
        }
        return unpack('G', $this->_data, $offset)[1];
    }

    /**
     * @throws WebAuthnException
     */
    public function getDoubleVal($offset)
    {
        if ($offset < 0 || ($offset + 8) > $this->_length) {
            throw new WebAuthnException('ByteBuffer: Invalid offset', WebAuthnException::BYTEBUFFER);
        }
        return unpack('E', $this->_data, $offset)[1];
    }

    /**
     * @return string
     */
    public function getBinaryString(): string
    {
        return $this->_data;
    }

    /**
     * @param string|ByteBuffer $buffer
     * @return bool
     */
    public function equals(ByteBuffer|string $buffer): bool
    {
        if ($buffer instanceof ByteBuffer) {
            return $buffer->getBinaryString() === $this->getBinaryString();
        } else {
            return $buffer === $this->getBinaryString();
        }
    }

    /**
     * @return string
     */
    public function getHex(): string
    {
        return \bin2hex($this->_data);
    }

    /**
     * @return bool
     */
    public function isEmpty(): bool
    {
        return $this->_length === 0;
    }


    /**
     * jsonSerialize interface
     * return binary data in RFC 1342-Like serialized string
     * @return string
     */
    public function jsonSerialize(): string
    {
        if (ByteBuffer::$useBase64UrlEncoding) {
            return self::_base64url_encode($this->_data);

        } else {
            return '=?BINARY?B?' . \base64_encode($this->_data) . '?=';
        }
    }

    /**
     * Serializable-Interface
     * @return string
     */
    public function serialize(): string
    {
        return \serialize($this->_data);
    }

    /**
     * Serializable-Interface
     * @param string $serialized
     */
    public function unserialize($serialized)
    {
        $this->_data = \unserialize($serialized);
        $this->_length = \strlen($this->_data);
    }

    /**
     * (PHP 8 deprecates Serializable-Interface)
     * @return array
     */
    public function __serialize(): array
    {
        return [
            'data' => \serialize($this->_data)
        ];
    }

    /**
     * object to string
     * @return string
     */
    public function __toString(): string
    {
        return $this->getHex();
    }

    /**
     * (PHP 8 deprecates Serializable-Interface)
     * @param array $data
     * @return void
     */
    public function __unserialize(array $data)
    {
        if ($data && isset($data['data'])) {
            $this->_data = \unserialize($data['data']);
            $this->_length = \strlen($this->_data);
        }
    }

    // -----------------------
    // PROTECTED STATIC
    // -----------------------

    /**
     * base64 url decoding
     * @param string $data
     * @return string
     */
    protected static function _base64url_decode(string $data): string
    {
        return \base64_decode(\strtr($data, '-_', '+/') . \str_repeat('=', 3 - (3 + \strlen($data)) % 4));
    }

    /**
     * base64 url encoding
     * @param string $data
     * @return string
     */
    protected static function _base64url_encode(string $data): string
    {
        return \rtrim(\strtr(\base64_encode($data), '+/', '-_'), '=');
    }
}
