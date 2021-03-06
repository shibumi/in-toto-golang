package in_toto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/ed25519"
)

// ErrFailedPEMParsing gets returned when PKCS1, PKCS8 or PKIX key parsing fails
var ErrFailedPEMParsing = errors.New("failed parsing the PEM block: unsupported PEM type")

// ErrNoPEMBlock gets triggered when there is no PEM block in the provided file
var ErrNoPEMBlock = errors.New("failed to decode the data as PEM block (are you sure this is a pem file?)")

// ErrUnsupportedKeyType is returned when we are dealing with a key type different to ed25519 or RSA
var ErrUnsupportedKeyType = errors.New("unsupported key type")

// ErrInvalidSignature is returned when the signature is invalid
var ErrInvalidSignature = errors.New("invalid signature")

// ErrInvalidKey is returned when a given key is none of RSA, ECDSA or ED25519
var ErrInvalidKey = errors.New("invalid key")

const (
	rsaKeyType            string = "rsa"
	ecdsaKeyType          string = "ecdsa"
	ed25519KeyType        string = "ed25519"
	rsassapsssha256Scheme string = "rsassa-pss-sha256"
	ecdsaSha2nistp224     string = "ecdsa-sha2-nistp224"
	ecdsaSha2nistp384     string = "ecdsa-sha2-nistp384"
	ecdsaSha2nistp521     string = "ecdsa-sha2-nistp521"
	ed25519Scheme         string = "ed25519"
	pemPublicKey          string = "PUBLIC KEY"
	pemPrivateKey         string = "PRIVATE KEY"
	pemRSAPrivateKey      string = "PRIVATE RSA KEY"
)

/*
getSupportedKeyIdHashAlgorithms returns a string slice of supported
keyIdHashAlgorithms. We need to use this function instead of a constant,
because Go does not support global constant slices.
*/
func getSupportedKeyIdHashAlgorithms() Set {
	return NewSet("sha256", "sha512")
}

/*
getSupportedRSASchemes returns a string slice of supported RSA Key schemes.
We need to use this function instead of a constant because Go does not support
global constant slices.
*/
func getSupportedRSASchemes() []string {
	return []string{rsassapsssha256Scheme}
}

/*
getSupportedEcdsaSchemes returns a string slice of supported ecdsa Key schemes.
We need to use this function instead of a constant because Go does not support
global constant slices.
*/
func getSupportedEcdsaSchemes() []string {
	return []string{ecdsaSha2nistp224, ecdsaSha2nistp384, ecdsaSha2nistp521}
}

/*
getSupportedEd25519Schemes returns a string slice of supported ed25519 Key
schemes. We need to use this function instead of a constant because Go does
not support global constant slices.
*/
func getSupportedEd25519Schemes() []string {
	return []string{ed25519Scheme}
}

/*
generateKeyID creates a partial key map and generates the key ID
based on the created partial key map via the SHA256 method.
The resulting keyID will be directly saved in the corresponding key object.
On success generateKeyID will return nil, in case of errors while encoding
there will be an error.
*/
func (k *Key) generateKeyID() error {
	// Create partial key map used to create the keyid
	// Unfortunately, we can't use the Key object because this also carries
	// yet unwanted fields, such as KeyId and KeyVal.Private and therefore
	// produces a different hash. We generate the keyId exactly as we do in
	// the securesystemslib  to keep interoperability between other in-toto
	// implementations.
	var keyToBeHashed = map[string]interface{}{
		"keytype":               k.KeyType,
		"scheme":                k.Scheme,
		"keyid_hash_algorithms": k.KeyIdHashAlgorithms,
		"keyval": map[string]string{
			"public": k.KeyVal.Public,
		},
	}
	keyCanonical, err := EncodeCanonical(keyToBeHashed)
	if err != nil {
		return err
	}
	// calculate sha256 and return string representation of keyId
	keyHashed := sha256.Sum256(keyCanonical)
	k.KeyId = fmt.Sprintf("%x", keyHashed)
	err = validateKey(*k)
	if err != nil {
		return err
	}
	return nil
}

/*
generatePEMBlock creates a PEM block from scratch via the keyBytes and the pemType.
If successful it returns a PEM block as []byte slice. This function should always
succeed, if keyBytes is empty the PEM block will have an empty byte block.
Therefore only header and footer will exist.
*/
func generatePEMBlock(keyBytes []byte, pemType string) []byte {
	// construct PEM block
	pemBlock := &pem.Block{
		Type:    pemType,
		Headers: nil,
		Bytes:   keyBytes,
	}
	return pem.EncodeToMemory(pemBlock)
}

/*
setKeyComponents sets all components in our key object.
Furthermore it makes sure to remove any trailing and leading whitespaces or newlines.
We treat key types differently for interoperability reasons to the in-toto python
implementation and the securesystemslib.
*/
func (k *Key) setKeyComponents(pubKeyBytes []byte, privateKeyBytes []byte, keyType string, scheme string, keyIdHashAlgorithms []string) error {
	// assume we have a privateKey if the key size is bigger than 0
	switch keyType {
	case rsaKeyType:
		if len(privateKeyBytes) > 0 {
			k.KeyVal = KeyVal{
				Private: strings.TrimSpace(string(generatePEMBlock(privateKeyBytes, pemRSAPrivateKey))),
				Public:  strings.TrimSpace(string(generatePEMBlock(pubKeyBytes, pemPublicKey))),
			}
		} else {
			k.KeyVal = KeyVal{
				Public: strings.TrimSpace(string(generatePEMBlock(pubKeyBytes, pemPublicKey))),
			}
		}
	case ecdsaKeyType:
		if len(privateKeyBytes) > 0 {
			k.KeyVal = KeyVal{
				Private: strings.TrimSpace(string(generatePEMBlock(privateKeyBytes, pemPrivateKey))),
				Public:  strings.TrimSpace(string(generatePEMBlock(pubKeyBytes, pemPublicKey))),
			}
		} else {
			k.KeyVal = KeyVal{
				Public: strings.TrimSpace(string(generatePEMBlock(pubKeyBytes, pemPublicKey))),
			}
		}
	case ed25519KeyType:
		if len(privateKeyBytes) > 0 {
			k.KeyVal = KeyVal{
				Private: strings.TrimSpace(hex.EncodeToString(privateKeyBytes)),
				Public:  strings.TrimSpace(hex.EncodeToString(pubKeyBytes)),
			}
		} else {
			k.KeyVal = KeyVal{
				Public: strings.TrimSpace(hex.EncodeToString(pubKeyBytes)),
			}
		}
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedKeyType, keyType)
	}
	k.KeyType = keyType
	k.Scheme = scheme
	k.KeyIdHashAlgorithms = keyIdHashAlgorithms
	if err := k.generateKeyID(); err != nil {
		return err
	}
	return nil
}

/*
parseKey tries to parse a PEM []byte slice. Using the following standards
in the given order:

	* PKCS8
	* PKCS1
	* PKIX

On success it returns the parsed key and nil.
On failure it returns nil and the error ErrFailedPEMParsing
*/
func parseKey(data []byte) (interface{}, error) {
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err == nil {
		return key, nil
	}
	key, err = x509.ParsePKCS1PrivateKey(data)
	if err == nil {
		return key, nil
	}
	key, err = x509.ParsePKIXPublicKey(data)
	if err == nil {
		return key, nil
	}
	return nil, ErrFailedPEMParsing
}

/*
decodeAndParse receives potential PEM bytes decodes them via pem.Decode
and pushes them to parseKey. If any error occurs during this process,
the function will return nil and an error (either ErrFailedPEMParsing
or ErrNoPEMBlock). On success it will return the decoded pemData, the
key object interface and nil as error. We need the decoded pemData,
because LoadKey relies on decoded pemData for operating system
interoperability.
*/
func decodeAndParse(pemBytes []byte) (*pem.Block, interface{}, error) {
	// pem.Decode returns the parsed pem block and a rest.
	// The rest is everything, that could not be parsed as PEM block.
	// Therefore we can drop this via using the blank identifier "_"
	data, _ := pem.Decode(pemBytes)
	if data == nil {
		return nil, nil, ErrNoPEMBlock
	}
	// Try to load private key, if this fails try to load
	// key as public key
	key, err := parseKey(data.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return data, key, nil
}

/*
LoadKey loads the key file at specified file path into the key object.
It automatically derives the PEM type and the key type.
Right now the following PEM types are supported:

	* PKCS1 for private keys
	* PKCS8	for private keys
	* PKIX for public keys

The following key types are supported and will be automatically assigned to
the key type field:

	* ed25519
	* rsa
	* ecdsa

The following schemes are supported:

	* ed25519 -> ed25519
	* rsa -> rsassa-pss-sha256
	* ecdsa -> ecdsa-sha256-nistp256

Note that, this behavior is consistent with the securesystemslib, except for
ecdsa. We do not use the scheme string as key type in in-toto-golang.
Instead we are going with a ecdsa/ecdsa-sha2-nistp256 pair.

On success it will return nil. The following errors can happen:

	* path not found or not readable
	* no PEM block in the loaded file
	* no valid PKCS8/PKCS1 private key or PKIX public key
	* errors while marshalling
	* unsupported key types
*/
func (k *Key) LoadKey(path string, scheme string, keyIdHashAlgorithms []string) error {
	pemFile, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := pemFile.Close(); closeErr != nil {
			err = closeErr
		}
	}()
	return k.LoadKeyReader(pemFile, scheme, keyIdHashAlgorithms)
}

// LoadKeyReader loads the key from a supplied reader. The logic matches LoadKey otherwise.
func (k *Key) LoadKeyReader(r io.Reader, scheme string, keyIdHashAlgorithms []string) error {
	if r == nil {
		return ErrNoPEMBlock
	}
	// Read key bytes
	pemBytes, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}
	// decodeAndParse returns the pemData for later use
	// and a parsed key object (for operations on that key, like extracting the public Key)
	pemData, key, err := decodeAndParse(pemBytes)
	if err != nil {
		return err
	}

	// Use type switch to identify the key format
	switch key.(type) {
	case *rsa.PublicKey:
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(key.(*rsa.PublicKey))
		if err != nil {
			return err
		}
		if err := k.setKeyComponents(pubKeyBytes, []byte{}, rsaKeyType, scheme, keyIdHashAlgorithms); err != nil {
			return err
		}
	case *rsa.PrivateKey:
		// Note: RSA Public Keys will get stored as X.509 SubjectPublicKeyInfo (RFC5280)
		// This behavior is consistent to the securesystemslib
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(key.(*rsa.PrivateKey).Public())
		if err != nil {
			return err
		}
		if err := k.setKeyComponents(pubKeyBytes, pemData.Bytes, rsaKeyType, scheme, keyIdHashAlgorithms); err != nil {
			return err
		}
	case ed25519.PublicKey:
		if err := k.setKeyComponents(key.(ed25519.PublicKey), []byte{}, ed25519KeyType, scheme, keyIdHashAlgorithms); err != nil {
			return err
		}
	case ed25519.PrivateKey:
		pubKeyBytes := key.(ed25519.PrivateKey).Public()
		if err := k.setKeyComponents(pubKeyBytes.(ed25519.PublicKey), key.(ed25519.PrivateKey), ed25519KeyType, scheme, keyIdHashAlgorithms); err != nil {
			return err
		}
	case *ecdsa.PrivateKey:
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(key.(*ecdsa.PrivateKey).Public())
		if err != nil {
			return err
		}
		if err := k.setKeyComponents(pubKeyBytes, pemData.Bytes, ecdsaKeyType, scheme, keyIdHashAlgorithms); err != nil {
			return err
		}
	case *ecdsa.PublicKey:
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(key.(*ecdsa.PublicKey))
		if err != nil {
			return err
		}
		if err := k.setKeyComponents(pubKeyBytes, []byte{}, ecdsaKeyType, scheme, keyIdHashAlgorithms); err != nil {
			return err
		}
	default:
		// We should never get here, because we implement all from Go supported Key Types
		panic("unexpected Error in LoadKey function")
	}
	return nil
}

/*
GenerateSignature will automatically detect the key type and sign the signable data
with the provided key. If everything goes right GenerateSignature will return
a for the key valid signature and err=nil. If something goes wrong it will
return a not initialized signature and an error. Possible errors are:

	* ErrNoPEMBlock
	* ErrUnsupportedKeyType

Currently supported is only one scheme per key.

Note that in-toto-golang has different requirements to an ecdsa key.
In in-toto-golang we use the string 'ecdsa' as string for the key type.
In the key scheme we use: ecdsa-sha2-nistp256.
*/
func GenerateSignature(signable []byte, key Key) (Signature, error) {
	err := validateKey(key)
	if err != nil {
		return Signature{}, err
	}
	var signature Signature
	var signatureBuffer []byte
	hashMapping := getHashMapping()
	// The following switch block is needed for keeping interoperability
	// with the securesystemslib and the python implementation
	// in which we are storing RSA keys in PEM format, but ed25519 keys hex encoded.
	switch key.KeyType {
	case rsaKeyType:
		// We do not need the pemData here, so we can throw it away via '_'
		_, parsedKey, err := decodeAndParse([]byte(key.KeyVal.Private))
		if err != nil {
			return Signature{}, err
		}
		parsedKey, ok := parsedKey.(*rsa.PrivateKey)
		if !ok {
			return Signature{}, ErrKeyKeyTypeMismatch
		}
		switch key.Scheme {
		case rsassapsssha256Scheme:
			hashed := hashToHex(hashMapping["sha256"](), signable)
			// We use rand.Reader as secure random source for rsa.SignPSS()
			signatureBuffer, err = rsa.SignPSS(rand.Reader, parsedKey.(*rsa.PrivateKey), crypto.SHA256, hashed,
				&rsa.PSSOptions{SaltLength: sha256.Size, Hash: crypto.SHA256})
			if err != nil {
				return signature, err
			}
		default:
			// supported key schemes will get checked in validateKey
			panic("unexpected Error in GenerateSignature function")
		}
	case ecdsaKeyType:
		// We do not need the pemData here, so we can throw it away via '_'
		_, parsedKey, err := decodeAndParse([]byte(key.KeyVal.Private))
		if err != nil {
			return Signature{}, err
		}
		parsedKey, ok := parsedKey.(*ecdsa.PrivateKey)
		if !ok {
			return Signature{}, ErrKeyKeyTypeMismatch
		}
		curveSize := parsedKey.(*ecdsa.PrivateKey).Curve.Params().BitSize
		var hashed []byte
		if err := matchEcdsaScheme(curveSize, key.Scheme); err != nil {
			return Signature{}, ErrCurveSizeSchemeMismatch
		}
		// implement https://tools.ietf.org/html/rfc5656#section-6.2.1
		// We determine the curve size and choose the correct hashing
		// method based on the curveSize
		switch {
		case curveSize <= 256:
			hashed = hashToHex(hashMapping["sha256"](), signable)
		case 256 < curveSize && curveSize <= 384:
			hashed = hashToHex(hashMapping["sha384"](), signable)
		case curveSize > 384:
			hashed = hashToHex(hashMapping["sha512"](), signable)
		default:
			panic("unexpected Error in GenerateSignature function")
		}
		// ecdsa.Sign returns a signature that consists of two components called: r and s
		// We assume here, that r and s are of the same size nLen and that
		// the signature is 2*nLen. Furthermore we must note  that hashes get truncated
		// if they are too long for the curve.
		r, s, err := ecdsa.Sign(rand.Reader, parsedKey.(*ecdsa.PrivateKey), hashed)
		if err != nil {
			return signature, nil
		}
		// Generate the ecdsa signature on the same way, as we do in the securesystemslib
		// We are marshalling the ecdsaSignature struct as ASN.1 INTEGER SEQUENCES
		// into an ASN.1 Object.
		signatureBuffer, err = asn1.Marshal(EcdsaSignature{
			R: r,
			S: s,
		})
	case ed25519KeyType:
		// We do not need a scheme switch here, because ed25519
		// only consist of sha256 and curve25519.
		privateHex, err := hex.DecodeString(key.KeyVal.Private)
		if err != nil {
			return signature, ErrInvalidHexString
		}
		// Note: We can directly use the key for signing and do not
		// need to use ed25519.NewKeyFromSeed().
		signatureBuffer = ed25519.Sign(privateHex, signable)
	default:
		// We should never get here, because we call validateKey in the first
		// line of the function.
		panic("unexpected Error in GenerateSignature function")
	}
	signature.Sig = hex.EncodeToString(signatureBuffer)
	signature.KeyId = key.KeyId
	return signature, nil
}

/*
VerifySignature will verify unverified byte data via a passed key and signature.
Supported key types are:

	* rsa
	* ed25519
	* ecdsa

When encountering an RSA key, VerifySignature will decode the PEM block in the key
and will call rsa.VerifyPSS() for verifying the RSA signature.
When encountering an ed25519 key, VerifySignature will decode the hex string encoded
public key and will use ed25519.Verify() for verifying the ed25519 signature.
When the given key is an ecdsa key, VerifySignature will unmarshall the ASN1 object
and will use the retrieved ecdsa components 'r' and 's' for verifying the signature.
On success it will return nil. In case of an unsupported key type or any other error
it will return an error.

Note that in-toto-golang has different requirements to an ecdsa key.
In in-toto-golang we use the string 'ecdsa' as string for the key type.
In the key scheme we use: ecdsa-sha2-nistp256.
*/
func VerifySignature(key Key, sig Signature, unverified []byte) error {
	err := validateKey(key)
	if err != nil {
		return err
	}
	sigBytes, err := hex.DecodeString(sig.Sig)
	if err != nil {
		return err
	}
	hashMapping := getHashMapping()
	switch key.KeyType {
	case rsaKeyType:
		// We do not need the pemData here, so we can throw it away via '_'
		_, parsedKey, err := decodeAndParse([]byte(key.KeyVal.Public))
		if err != nil {
			return err
		}
		parsedKey, ok := parsedKey.(*rsa.PublicKey)
		if !ok {
			return ErrKeyKeyTypeMismatch
		}
		switch key.Scheme {
		case rsassapsssha256Scheme:
			hashed := hashToHex(hashMapping["sha256"](), unverified)
			err = rsa.VerifyPSS(parsedKey.(*rsa.PublicKey), crypto.SHA256, hashed, sigBytes, &rsa.PSSOptions{SaltLength: sha256.Size, Hash: crypto.SHA256})
			if err != nil {
				return fmt.Errorf("%w: %s", ErrInvalidSignature, err)
			}
		default:
			// supported key schemes will get checked in validateKey
			panic("unexpected Error in VerifySignature function")
		}
	case ecdsaKeyType:
		var ecdsaSignature EcdsaSignature
		// We do not need the pemData here, so we can throw it away via '_'
		_, parsedKey, err := decodeAndParse([]byte(key.KeyVal.Public))
		if err != nil {
			return err
		}
		parsedKey, ok := parsedKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrKeyKeyTypeMismatch
		}
		curveSize := parsedKey.(*ecdsa.PublicKey).Curve.Params().BitSize
		var hashed []byte
		if err := matchEcdsaScheme(curveSize, key.Scheme); err != nil {
			return ErrCurveSizeSchemeMismatch
		}
		// implement https://tools.ietf.org/html/rfc5656#section-6.2.1
		// We determine the curve size and choose the correct hashing
		// method based on the curveSize
		switch {
		case curveSize <= 256:
			hashed = hashToHex(hashMapping["sha256"](), unverified)
		case 256 < curveSize && curveSize <= 384:
			hashed = hashToHex(hashMapping["sha384"](), unverified)
		case curveSize > 384:
			hashed = hashToHex(hashMapping["sha512"](), unverified)
		default:
			panic("unexpected Error in VerifySignature function")
		}
		// Unmarshal the ASN.1 DER marshalled ecdsa signature to
		// ecdsaSignature. asn1.Unmarshal returns the rest and an error
		// we can skip the rest here..
		_, err = asn1.Unmarshal(sigBytes, &ecdsaSignature)
		if err != nil {
			return err
		}
		if err := ecdsa.Verify(parsedKey.(*ecdsa.PublicKey), hashed, ecdsaSignature.R, ecdsaSignature.S); err == false {
			return ErrInvalidSignature
		}
	case ed25519KeyType:
		// We do not need a scheme switch here, because ed25519
		// only consist of sha256 and curve25519.
		pubHex, err := hex.DecodeString(key.KeyVal.Public)
		if err != nil {
			return ErrInvalidHexString
		}
		if ok := ed25519.Verify(pubHex, unverified, sigBytes); !ok {
			return fmt.Errorf("%w: ed25519", ErrInvalidSignature)
		}
	default:
		// We should never get here, because we call validateKey in the first
		// line of the function.
		panic("unexpected Error in VerifySignature function")
	}
	return nil
}
