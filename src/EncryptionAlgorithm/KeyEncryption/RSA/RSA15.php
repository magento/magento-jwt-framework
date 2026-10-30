<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use function func_get_arg;
use function func_num_args;
use InvalidArgumentException;
use function is_int;
use function is_string;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\RSAKey;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\RSACrypt;

final class RSA15 extends RSA
{
    /**
     * Compatibility fallback for direct calls without the selected algorithm's CEK size.
     */
    private const CEK_LENGTHS = [
        'A128GCM' => 16,
        'A192GCM' => 24,
        'A256GCM' => 32,
        'A128CBC-HS256' => 32,
        'A192CBC-HS384' => 48,
        'A256CBC-HS512' => 64,
    ];

    public function name(): string
    {
        return 'RSA1_5';
    }

    /**
     * An undeclared fourth argument supplies the content algorithm's CEK size in bits.
     */
    public function decryptKey(JWK $key, string $encrypted_cek, array $header): string
    {
        $encryptionKeyLength = func_num_args() > 3 ? func_get_arg(3) : null;
        $this->checkKey($key);
        if (!$key->has('d')) {
            throw new InvalidArgumentException('The key is not a private key');
        }
        $priv = RSAKey::createFromJWK($key);

        return RSACrypt::decrypt($priv, $encrypted_cek, RSACrypt::ENCRYPTION_PKCS1, null, $this->getExpectedCekLength($header, $encryptionKeyLength));
    }

    protected function getEncryptionMode(): int
    {
        return RSACrypt::ENCRYPTION_PKCS1;
    }

    protected function getHashAlgorithm(): ?string
    {
        return null;
    }

    /**
     * @param mixed $encryptionKeyLength The selected content algorithm's CEK size in bits
     */
    private function getExpectedCekLength(array $header, $encryptionKeyLength): int
    {
        if (is_int($encryptionKeyLength)) {
            return intdiv($encryptionKeyLength, 8);
        }
        $enc = $header['enc'] ?? null;
        if (!is_string($enc) || !isset(self::CEK_LENGTHS[$enc])) {
            throw new InvalidArgumentException('RSA1_5 decryption requires the content algorithm CEK size or a supported "enc" parameter.');
        }

        return self::CEK_LENGTHS[$enc];
    }
}
