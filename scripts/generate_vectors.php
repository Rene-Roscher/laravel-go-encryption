<?php

declare(strict_types=1);

// Generates Laravel->Go test vectors using the REAL Laravel Encrypter, written to
// fixtures/vectors.json. The Go test TestDecryptGeneratedVectors then decrypts them.

require __DIR__.'/../vendor/autoload.php';

use Illuminate\Encryption\Encrypter;

$rawKey = str_repeat("\x2b", 32); // fixed, reproducible
$keyB64 = base64_encode($rawKey);

$plaintexts = [
    'simple' => 'Hello, World!',
    'empty' => '',
    'unicode' => 'Grüße 世界 🚀 café',
    'json' => json_encode(['user' => 'alice', 'id' => 7, 'active' => true, 'tags' => ['x', 'y']]),
    'multiline' => "first line\nsecond line\n\tindented\n",
    'long' => str_repeat('The quick brown fox 0123456789 ', 50),
];

$vectors = [];
foreach (['aes-256-cbc', 'aes-256-gcm'] as $cipher) {
    $enc = new Encrypter($rawKey, $cipher);
    foreach ($plaintexts as $name => $pt) {
        $vectors[] = [
            'name' => "{$cipher}/{$name}",
            'cipher' => $cipher,
            'plaintext' => $pt,
            'payload' => $enc->encryptString($pt),
        ];
    }
}

@mkdir(__DIR__.'/../fixtures', 0o755, true);
file_put_contents(
    __DIR__.'/../fixtures/vectors.json',
    json_encode(['key_b64' => $keyB64, 'vectors' => $vectors], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n"
);

fwrite(STDERR, 'Wrote '.count($vectors)." Laravel vectors to fixtures/vectors.json\n");
