<?php

declare(strict_types=1);

// Reads {key, vectors:[{kind,cipher,plaintext,payload}]} JSON on STDIN (produced by
// `go run ./cmd/genvectors`), decrypts each with the REAL Laravel Encrypter, and asserts
// equality. Exits non-zero on any mismatch — proving the Go -> Laravel direction for both
// the string path (decryptString) and the serialized path (decrypt).

require __DIR__.'/../vendor/autoload.php';

use Illuminate\Encryption\Encrypter;

$input = stream_get_contents(STDIN);
$data = json_decode($input, true);

if (! is_array($data) || ! isset($data['key'], $data['vectors'])) {
    fwrite(STDERR, "Invalid input JSON\n");
    exit(2);
}

$key = $data['key'];
$rawKey = str_starts_with($key, 'base64:') ? base64_decode(substr($key, 7)) : $key;

// Must match the structure encoded by cmd/genvectors.
$expectedTyped = ['user' => 'alice', 'id' => 7, 'active' => true, 'score' => 2.5, 'tags' => ['x', 'y'], 'meta' => null];

$failures = 0;
foreach ($data['vectors'] as $v) {
    $enc = new Encrypter($rawKey, $v['cipher']);
    try {
        if (($v['kind'] ?? 'string') === 'serialized') {
            $got = $enc->decrypt($v['payload']);
            $ok = ($got == $expectedTyped); // loose: array key order is irrelevant
        } else {
            $got = $enc->decryptString($v['payload']);
            $ok = ($got === $v['plaintext']);
        }
    } catch (\Throwable $e) {
        $ok = false;
        $got = 'EXCEPTION: '.$e->getMessage();
    }
    if ($ok) {
        fwrite(STDERR, "OK   [{$v['cipher']}/{$v['kind']}]\n");
    } else {
        $failures++;
        fwrite(STDERR, "FAIL [{$v['cipher']}/{$v['kind']}] got=".var_export($got, true)."\n");
    }
}

if ($failures > 0) {
    fwrite(STDERR, "{$failures} Go->Laravel vector(s) failed\n");
    exit(1);
}
fwrite(STDERR, "All Go->Laravel vectors decrypted correctly\n");
