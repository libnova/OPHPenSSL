<?php

require_once("openssl_lib.php");

$ssl_lib = new OpenSSL_Lib();

if(!$ssl_lib->check_ssl()){
	die("PHP Open-SSL Support not enabled");
}

$url = !empty($_GET['fqdn']) ? $_GET['fqdn'] : '';
if(empty($url)){
	die("Certificate FQDN not specified.");
}

$cert_config = array(
	'password' => 'dummy_password',
	'validity' => 3650,
);

$pkey_config = array(
	"digest_alg" => "sha512",
	"private_key_bits" => 4096,
	"private_key_type" => OPENSSL_KEYTYPE_RSA,
);

// Generate CA files if they don't exist
if(!$ssl_lib->ca_exists()){	
	// CA Root Data
	$csr_config = array(
		"countryName"            => "ES",
		"stateOrProvinceName"    => "Madrid",
		"localityName"           => "Madrid",
		"organizationName"       => "DummyOrganization",
		"organizationalUnitName" => "DummyOrganizationDepartment",
		"commonName"             => "DummyOrganization SelfSigned CACert",
		"emailAddress"           => "dummy@localhost.com"
	);

	$ssl_lib->generate_cacert(
		$csr_config,
		$cert_config,
		$pkey_config
	);
}

// If CA files were correctly created
if($ssl_lib->load_ca($cert_config['password']) && !empty($url)){
	$csr_config = array(
		"countryName"            => "ES",
		"stateOrProvinceName"    => "Madrid",
		"localityName"           => "Madrid",
		"organizationName"       => "DummyOrganization",
		"organizationalUnitName" => "DummyOrganizationDepartment",
		"commonName"             => $url,
		"emailAddress"           => "dummy@localhost.com"
	);

	$csr_data = $ssl_lib->generate_csr($csr_config);
	$ssl_lib->store_csr_data($csr_data, $url);
	$cert = $ssl_lib->sign_csr($csr_data, $cert_config);

	//$ssl_lib->download_cert($cert, $url);
	
	$signed_cert = $ssl_lib->get_exportable_cert($cert);
	$priv_key    = $ssl_lib->get_exportable_key_private();
	$pub_key     = $ssl_lib->get_exportable_key_public();

	$zip = new ZipArchive();
	$zip_filename = $url.".zip";
	$zip_filepath = tempnam(sys_get_temp_dir(), 'openssl_lib');
	
	$zip->open($zip_filepath, ZipArchive::OVERWRITE);

	$zip->addFromString($url.".crt", $signed_cert);
	$zip->addFromString("private.key", $priv_key);
	$zip->addFromString("public.key", $pub_key);
	
	$zip->close();
		
	header('Content-Type: application/zip');
	header('Content-disposition: attachment; filename='.$zip_filename);
	header('Content-Length: ' . filesize($zip_filepath));
	readfile($zip_filepath);
	
	unlink($zip_filepath);
}

?>
