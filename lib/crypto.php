<?php

/**
	crypto functions
		these tend to evolve over time as cops and robbers devise new tricks
		for now, we are using built-in PHP functions
		18Sep2022 switched from mcrypt to openssl
**/

// 1. generate a unique key for use as session-id or remember-me token
function generateToken() {  // returns a hash string length 64
	global $ua_token_seed;
	$token = hash('sha256', Config::$ua_tokenseed.mt_rand());
	return $token;
}
function encryptToken($token) {
	$cipherToken = openssl_encrypt(
		$token,		        // the string to be encrypted
		'AES-256-CBC',		// cipher method
		Config::$ua_secretkey,	// passphrase
		0,			// options
		Config::$ua_initvector 	// initialization vector (iv)
	);
	$publicToken = base64_encode($cipherToken);
	return $publicToken;
}
function decryptToken($publicToken) {
	$cipherToken = base64_decode($publicToken);
	$token = openssl_decrypt(
		$cipherToken,		// the string to be decrypted
		'AES-256-CBC',		// cipher method
		Config::$ua_secretkey,	// passphrase
		0,			// options
		Config::$ua_initvector	// initialization vector (iv)
	);
	return $token;
}

// 2. generate a code for use as "temporary identification code" in email authorization
function generateTic() {  // returns all digits length 6
	// exclude problem chars: B8G6I1l0OQDS5Z2
	$characters = 'ACEFHJKMNPRTUVWXY4937';
	$string = '';
	$len = 6;
	for ($i = 0; $i < $len; $i++) {
		$string .= $characters[rand(0, strlen($characters) - 1)];
	}
	return $string;
}
// Using PHP functions.  The hashed string contains concatenated salt and algo.
function hashTic($publictic) {  // returns a hash string max length 255
	return password_hash($publictic, PASSWORD_DEFAULT);
}
function verifyTic($publictic, $hashtic) {  // returns a boolean
	return password_verify($publictic, $hashtic);
}

// 3. hash and verify a password
// Using PHP functions.  The hashed string contains concatenated salt and algo.
function hashPassword($password) {  // returns a hash string max length 255
	return password_hash($password, PASSWORD_DEFAULT);
}
function verifyPassword($password, $hashpassword) {  // returns a boolean
	return password_verify($password, $hashpassword);
}
?>
