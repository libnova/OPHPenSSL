<?php
$config = array(
	// CSR Default Config
	'csr_data' => array(
		"countryName"            => "XX",              // 2-digit country code
		"stateOrProvinceName"    => "Province",        // Province
		"localityName"           => "Locality",        // Locality
		"organizationName"       => "EnterpriseName",  // Organization Name
		"organizationalUnitName" => "DepartmentName",  // Organization Department Name
		"commonName"             => "localhost",       // FQDN for certificate requests
		"emailAddress"           => "email@domain.com" // Email address for certificate
	),
	'cert_data' => array(
		'password' => 'dummy_password',                // Password for private key sign
		'validity' => 365,                             // Cert validity time
	),
	'pkey_data' => array(
		"digest_alg" => "sha512",                      // Cert Digest Algorythm
		"private_key_bits" => 4096,                    // Private Key Size
		"private_key_type" => OPENSSL_KEYTYPE_RSA,     // Private Key Tipe
	),
);