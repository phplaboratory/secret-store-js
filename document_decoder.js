



/* from parity


/// Initialization vector length.
const INIT_VEC_LEN: usize = 16;



fn into_document_key(key: Bytes) -> Result<Bytes, Error> {
	// key is a previously distributely generated Public
	if key.len() != 64 {
		return Err(errors::invalid_params("key", "invalid public key length"));
	}

	// use x coordinate of distributely generated point as encryption key
	Ok(key[..INIT_VEC_LEN].into())
}


/// Encrypt document with distributely generated key.
pub fn encrypt_document(key: Bytes, document: Bytes) -> Result<Bytes, Error> {
	// make document key
	let key = into_document_key(key)?;

	// use symmetric encryption to encrypt document
	let iv = initialization_vector();
	let mut encrypted_document = vec![0; document.len() + iv.len()];
	{
		let (mut encryption_buffer, iv_buffer) = encrypted_document.split_at_mut(document.len());

		crypto::aes::encrypt_128_ctr(&key, &iv, &document, &mut encryption_buffer).map_err(errors::encryption)?;
		iv_buffer.copy_from_slice(&iv);
	}

	Ok(encrypted_document)
}



 */