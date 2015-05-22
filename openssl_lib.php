<?php

/**
 * OpenSSL Library for PHP
 */
class OpenSSL_Lib{
	/**
	 * Current path, so we don't need to generate it on every file request
	 * @var String
	 */
	private $current_path;
	
	/**
	 * Private Key Holder
	 * @var OpenSSL Object 
	 */
	private $private_key;
	
	/**
	 * Public Key Holder
	 * @var OpenSSL Object
	 */
	private $public_key;
	
	/**
	 * CARoot Cert
	 * @var OpenSSL Object
	 */
	private $caroot_cert;
	
	/**
	 * Default configurations
	 * @var mixed[]
	 */
	private $defaults = array(
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
	
	/**
	 * Generated certificates store
	 * @var String
	 */
	private $store   = 'store';
	
	/**
	 * CARoot Folder
	 * @var String
	 */
	private $ca_root = 'CA';

	##******************##
	# CONSTRUCTORS       #
	##******************#################################################
	
	/**
	 * Main construct
	 */
	public function __construct(){
		$this->_init();
	}

	##******************##
	# INIT FUNCTIONS    #
	##******************#################################################

	/**
	 * Load initial config
	 * @TODO make this work
	 */
	private function _load_config(){
		include_once("config.php");
	}
	
	/**
	 * Main init function.
	 * Externalized so it can be called so many times.
	 */
	private function _init(){
		$this->current_path = realpath(dirname(__FILE__));
		$this->load_ca();
	}
	
	/**
	 * Create new CA files to be able to sign new CSR.
	 * 
	 * @param mixed[] $csr_config  Config for self-signed certificate CSR
	 * @param mixed[] $cert_config Config for the resulting CA Cert
	 * @param mixed[] $pkey_config Config for the new Private Key
	 * 
	 * @return boolean TRUE on success. False on failure.
	 */
	public function generate_cacert($csr_config, $cert_config, $pkey_config){
		if(!$this->ca_exists()){
			$priv_key = $this->generate_priv_key($pkey_config);
			$csr_data = $this->generate_csr($csr_config, $priv_key);
			$cert     = $this->sign_csr($csr_data, $cert_config);
			
			$this->store_private_key($priv_key);
			$this->store_pem_cert($cert);

			return TRUE;
		}
		return FALSE;
	}
	
	/**
	 * Check if there are CA Root Files
	 * 
	 * @return bool True if CA files are here. False instead.
	 */
	public function ca_exists(){
		return
			file_exists($this->get_store_path('private_key')) &&
			file_exists($this->get_store_path('pem_cert')) &&
			file_exists($this->get_store_path('der_cert'));
	}
	
	/**
	 * Load CA data into OpenSSL object
	 * @param String $pkey_passphrase Private Key Passphrase
	 * @return boolean True if CA data was loaded successfully. False instead.
	 */
	public function load_ca($pkey_passphrase = ""){
		if($this->ca_exists()){
			if(empty($pkey_passphrase)){
				$this->private_key = openssl_pkey_get_private(
					file_get_contents($this->get_store_path('private_key'))
				);
			}
			else{
				$this->private_key = openssl_pkey_get_private(
					array(
						file_get_contents($this->get_store_path('private_key')),
						$pkey_passphrase
					)
				);
			}
			$this->caroot_cert = openssl_x509_read(file_get_contents($this->get_store_path('pem_cert')));
			
			var_dump($this->get_store_path('private_key'));
			
			return
				!empty($this->private_key) &&
				!empty($this->caroot_cert);
		}
		return FALSE;
	}

	##******************##
	# PUBLIC FUNCTIONS   #
	##******************#################################################
	
	/**
	 * Gets the currently stored private key for CA
	 * @return OpenSSL Object
	 */
	public function get_key_private(){
		return $this->private_key;
	}
	
	/**
	 * @TODO Get public key for current CA Cert
	 * @return OpenSSL Object
	 */
	public function get_key_public(){
		return $this->public_key;
	}
	
	/**
	 * Store CA private key
	 * @param type $data
	 */
	public function store_private_key($data){
		$this->_store_private_key($data);
	}

	/**
	 * Store CSR Data into file
	 * @param OpenSSL Object $data CSR Item to store
	 * @param String $filename Custom filename for given CSR Item
	 */
	public function store_csr_data($data, $filename = ""){
		$this->_store_csr_data($data, $filename);
	}

	/**
	 * Store PEM Cert into file
	 * @param OpenSSL Object $data CSR Item to store
	 * @param String $filename Custom filename for given CSR Item
	 */
	public function store_pem_cert($data, $filename = FALSE){
		$this->_store_pem_cert($data, $filename);
	}	

	/**
	 * Convert given PEM file into a DER one
	 * @param type $pem_file Path to PEM file
	 * 
	 * @return String Base64 Encoded DER file
	 */
	public function pem2der($pem_file){
		return $this->_pem2der(file_get_contents($pem_file));
	}

	/**
	 * Convert given DER file into a PEM one
	 * @param String $der_file Path to DER file
	 * 
	 * @return String Base64 Encoded PEM file
	 */
	public function der2pem($der_file){
		return $this->der2pem(file_get_contents($der_file));
	}
	
	public function generate_priv_key($key_data = FALSE, $force = FALSE){
		if(empty($this->private_key) || $force){
			$this->_generate_priv_key($key_data);
		}
		return $this->private_key;
	}
	
	/**
	 * Check if OpenSSL extension is currently loaded.
	 * 
	 * @return bool True if enabled. False instead.
	 */
	public function check_ssl(){
		return extension_loaded('openssl');
	}
	
	/**
	 * Check if the give Cert has been signed with the given Key
	 * 
	 * @param OpenSSL Object $cert Cert to check
	 * @param OpenSSL Object $key Key used (or not) to sign the certificate
	 * @param String $passphrase Key file passphrase
	 * 
	 * @return bool True if cert matches key. False instead.
	 */
	public function check_cert($cert, $key, $passphrase = ""){
		return openssl_x509_check_private_key(
			$cert,
			array(
				$key,
				$passphrase,
			)
		);
	}
	
	/**
	 * Generate a new Certificate Sign Request from request data
	 * 
	 * @param mixed[] $request_data CSR data to use when signing
	 * @param OpenSSL Object $private_key Private key to sign the CSR with
	 * 
	 * @return OpenSSL Object OpenSSL Object with the newly generated Certificate Sign Request
	 */
	public function generate_csr($request_data = FALSE, $private_key = FALSE){
		if($request_data !== FALSE && is_array($request_data)){
			foreach($request_data as $request_data_field=>$request_data_value){
				if(!empty($this->defaults['csr_data'][$request_data_field])){
					$this->defaults['csr_data'][$request_data_field] = $request_data_value;
				}
			}
		}
		if($private_key === FALSE){
			$private_key = $this->private_key;
		}
		return openssl_csr_new($this->defaults['csr_data'], $private_key);
	}
	
	/**
	 * Generates a full download request for cert
	 * @param type $cert OpenSSL Object Certificate
	 * @param type $type Output type (X509, CSR, PKCS10 or PKCS12)
	 * @param type $outformat Output format ('der' or 'pem');
	 */
	public function download_cert($cert, $cert_name = 'signed_certificate_', $type = 'X509', $outformat = 'der'){
		$outformat = strtolower($outformat);
		$cert_ext = FALSE;

		switch(strtoupper($type)){
			case 'X509':
				header('Content-type: application/x-x509-ca-cert');
				openssl_x509_export($cert, $cert_ext);
				break;
			case 'CSR':
				$outformat = 'csr';
			case 'PKCS10':
				$outformat = 'p10';
				header('Content-type: application/pkcs10 ');
				openssl_csr_export($cert, $cert_ext);
				break;
			case 'PKCS12':
				$outformat = 'p12';
				header('Content-type: application/x-pkcs12');
				openssl_pkcs12_export($cert, $cert_ext);
				break;
		}
		
		if(strtolower($outformat) === 'pem'){
			header('Content-type: application/x-pem-file', TRUE);
			$cert_ext = $this->_der2pem($cert_ext);
		}

		header('Content-Disposition: attachment; filename="'.$cert_name.strtoupper($type).'.'.$outformat.'"');
		echo $cert_ext;
	}
	
	/**
	 * Get the Base64 Encoded certificate from OpenSSL Object
	 * @param OpenSSL X509 Object $cert Certificate to convert to its Base64 Encoded form
	 * @return String Base64 Encoded certificate
	 */
	public function get_exportable_cert($cert = FALSE){
		if($cert === FALSE){
			return FALSE;
		}
		$exportable_cert = FALSE;
		openssl_x509_export($cert, $exportable_cert);
		return $exportable_cert;
	}
	
	/**
	 * Get Base64 Encoded private key from OpenSSL Object
	 * @param OpenSSL Object $key Key to convert to its Base64 Encoded form
	 * 
	 * @return String Base64 Encoded private key
	 */
	public function get_exportable_key_private($key = FALSE){
		if($key === FALSE){
			$key = $this->private_key;
		}
		$exportable_key = FALSE;
		openssl_pkey_export($key, $exportable_key);
		return $exportable_key;
	}
	
	/**
	 * Get Base64 Encoded private key from private key in form of OpenSSL Object
	 * @param OpenSSL Object $key Private key to get the public key from
	 * 
	 * @return String Base64 Encoded public key
	 */
	public function get_exportable_key_public($key = FALSE){
		if($key === FALSE){
			$key = $this->private_key;
		}
		$public_key = openssl_pkey_get_details($key);
		$exportable_key = $public_key["key"];
		return $exportable_key;
	}
	
	/**
	 * Get Base64 Encoded public key from certificate file
	 * @param OpenSSL X509 Object $cert Certificate to get the public key from
	 * 
	 * @return String Base64 Encoded public key
	 */
	public function get_exportable_key_public_from_cert($cert = FALSE){
		if($cert === FALSE){
			return FALSE;
		}
		$public_key = openssl_pkey_get_public($cert);
		$public_key_data = openssl_pkey_get_details($public_key);
		$exportable_key = $public_key_data['key'];
		return $exportable_key;
	}

	
	##******************##
	# PRIVATE FUNCTIONS  #
	##******************#################################################
	
	/**
	 * Store given private key in CA folder
	 * @param OpenSSL Object $data OpenSSL PKey Object to store
	 */
	private function _store_private_key($data){
		$private_key_file = $this->get_store_path('private_key');
		openssl_pkey_export_to_file($data, $private_key_file, $this->defaults['cert_data']['password']);
	}

	/**
	 * Store given csr data in main store folder
	 * 
	 * @param OpenSSL Object $data OpenSSL CSR Object to store
	 * @param String $filename Output file name for CSR file
	 */
	private function _store_csr_data($data, $filename = ""){
		$csr_data_file = $this->get_store_path('csr_data', $filename);
		openssl_csr_export_to_file($data, $csr_data_file);
	}

	/**
	 * Store given pem certificate data in main store folder
	 * 
	 * @param OpenSSL Object $data OpenSSL x509 Object to store
	 * @param String $filename Output file name for PEM file
	 */
	private function _store_pem_cert($data, $filename = FALSE){
		$pem_cert_file = '';
		if($filename === FALSE){
			$pem_cert_file = $this->get_store_path('pem_cert');
		}else{
			$pem_cert_file = $this->get_store_path().$filename.".pem";
		}
		openssl_x509_export_to_file($data, $pem_cert_file);
		
		$this->_store_der_cert($this->pem2der($pem_cert_file));
	}

	/**
	 * Store given der certificate data in main store folder
	 * 
	 * @param String $data Base64 Encoded der cert
	 * @param String $filename Output file name for DER file
	 */
	private function _store_der_cert($data, $filename = FALSE){
		$der_cert_file = '';
		if($filename === FALSE){
			$der_cert_file = $this->get_store_path('der_cert');
		}else{
			$der_cert_file = $this->get_store_path().$filename.".der";
		}
		file_put_contents($der_cert_file, $data);
	}
	

	/**
	 * Converts PEM data into DER data
	 * @param String $pem_data Base64 Encoded PEM data
	 * 
	 * @return string Base64 Encoded DER data
	 */
	private function _pem2der($pem_data) {
		$begin = "CERTIFICATE-----";
		$end   = "-----END";
		$pem_data = substr($pem_data, strpos($pem_data, $begin)+strlen($begin));    
		$pem_data = substr($pem_data, 0, strpos($pem_data, $end));
		$der = base64_decode($pem_data);
		return $der;
	}

	/**
	 * Converts DER data into PEM data
	 * @param String $der_data Base64 Encoded DER data
	 * 
	 * @return string Base64 Encoded PEM data
	 */
	private function _der2pem($der_data) {
		$pem = chunk_split(base64_encode($der_data), 64, "\n");
		$pem = "-----BEGIN CERTIFICATE-----\n".$pem."-----END CERTIFICATE-----\n";
		return $pem;
	}

	/**
	 * Get path for different file types handled by the library
	 * @param String $file File to retrieve path
	 * @param String $custom_filename Custom filename. Useful for separating domain CSR requests, for example.
	 * 
	 * @return string The resulting file path
	 */
	private function get_store_path($file = FALSE, $custom_filename = FALSE){
		$basepath = $this->current_path.DIRECTORY_SEPARATOR;
		switch($file){
			case 'private_key':
				$filename = !empty($custom_filename) ? $custom_filename.DIRECTORY_SEPARATOR : '';
				$filename = $filename . 'private';
				return $basepath.$this->ca_root.DIRECTORY_SEPARATOR.$filename.'.key';
				break;
			case 'public_key':
				$filename = !empty($custom_filename) ? $custom_filename.DIRECTORY_SEPARATOR : '';
				$filename = $filename . 'public';
				return $basepath.$this->ca_root.DIRECTORY_SEPARATOR.$filename.'.key';
				break;
			case 'pem_cert':
				$filename = !empty($custom_filename) ? $custom_filename.DIRECTORY_SEPARATOR : '';
				$filename = $filename . 'caroot';
				return $basepath.$this->ca_root.DIRECTORY_SEPARATOR.$filename.'.pem';
				break;
			case 'der_cert':
				$filename = !empty($custom_filename) ? $custom_filename.DIRECTORY_SEPARATOR : '';
				$filename = $filename . 'caroot';
				return $basepath.$this->ca_root.DIRECTORY_SEPARATOR.$filename.'.der';
				break;
			case 'csr_data':
				$filename = !empty($custom_filename) ? $custom_filename.DIRECTORY_SEPARATOR : '';
				$filename = $filename . 'caroot';
				return $basepath.$this->store.DIRECTORY_SEPARATOR.$filename.'.csr';
				break;
			case 'openssl_conf':
				return $basepath.$this->store.DIRECTORY_SEPARATOR."openssl.conf";
				break;
			case 'store':
				return $basepath.$this->store.DIRECTORY_SEPARATOR;
				break;
			default:
				return $basepath;
				break;
		}
	}
	
	/**
	 * Inner private key generator. Can be forced to re-generate a new private key.
	 * 
	 * @param mixed[] $key_data Config used for new private key.
	 */
	private function _generate_priv_key($key_data = FALSE){
		if($key_data !== FALSE && is_array($key_data)){
			foreach($key_data as $key_data_field=>$key_data_value){
				if(!empty($this->defaults['pkey_data'][$key_data_field])){
					$this->defaults['pkey_data'][$key_data_field] = $key_data_value;
				}
			}
		}
	
		$this->private_key = openssl_pkey_new($this->defaults['pkey_data']);
	}
	
	/**
	 * Signs a Certificate Signing Request with the given certificate or the main CA Cert instead
	 * 
	 * @param type $csr_data CSR to sign
	 * @param type $cert_data 
	 * @param type $cacert
	 * @return OpenSSL Object The signed request
	 */
	public function sign_csr($csr_data = FALSE, $cert_data = FALSE, $cacert = NULL){
		if($cert_data !== FALSE && is_array($cert_data)){
			foreach($cert_data as $cert_data_field=>$cert_data_value){
				if(!empty($this->defaults['cert_data'][$cert_data_field])){
					$this->defaults['cert_data'][$cert_data_field] = $cert_data_value;
				}
			}
		}

		if($cacert === NULL){
			if(!empty($this->caroot_cert)){
				$cacert = $this->caroot_cert;
			}
		}
		
		$cacert_exportable = NULL;
		if($cacert !== NULL){
			openssl_x509_export($cacert, $cacert_exportable);
		}
				
		return openssl_csr_sign(
			$csr_data,
			$cacert_exportable,
			$this->get_key_private(),
			$this->defaults['cert_data']['validity']
		);
	}
}