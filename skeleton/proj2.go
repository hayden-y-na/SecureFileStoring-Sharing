// Notes:
// example how to print to terminal
// fmt.Println(err)

package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib
	"github.com/nweaver/cs161-p2/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"
	
	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// For the useful little debug printing function
	"fmt"
	"time"
	"os"
	"strings"

	// I/O
	"io"
	
	// Want to import errors
	"errors"
	
	// These are imported for the structure definitions.  You MUST
	// not actually call the functions however!!!
	// You should ONLY call the cryptographic functions in the
	// userlib, as for testing we may add monitoring functions.
	// IF you call functions in here directly, YOU WILL LOSE POINTS
	// EVEN IF YOUR CODE IS CORRECT!!!!!
	"crypto/rsa"
)


// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings(){
	// Creates a random UUID
	f := uuid.New()
	debugMsg("UUID as string:%v", f.String())
	
	// Example of writing over a byte of f
	f[0] = 10
	debugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	debugMsg("The hex: %v", h)
	
	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d,_ := json.Marshal(f)
	debugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	debugMsg("Unmarshaled data %v", g.String())

	// This creates an error type
	debugMsg("Creation of error %v", errors.New("This is an error"))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *rsa.PrivateKey
	key,_ = userlib.GenerateRSAKey()
	debugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range(ret){
		ret[x] = data[x]
	}
	return
}

// Helper function: Returns a byte slice of the specificed
// size filled with random data
func randomBytes(bytes int) (data []byte){
	data = make([]byte, bytes)
	if _, err := io.ReadFull(userlib.Reader, data); err != nil {
		panic(err)
	}
	return
}

var DebugPrint = false

// Helper function: Does formatted printing to stderr if
// the DebugPrint global is set.  All our testing ignores stderr,
// so feel free to use this for any sort of testing you want
func debugMsg(format string, args ...interface{}) {
	if DebugPrint{
		msg := fmt.Sprintf("%v ", time.Now().Format("15:04:05.00000"))
		fmt.Fprintf(os.Stderr,
			msg + strings.Trim(format, "\r\n ") + "\n", args...)
	}
}


// The structure definition for a user record
type User struct {
	Username string //PBKDF'ed username
	KeyA []byte //Key for Authentication
	KeyE []byte //Key for Encryption
	KeyN []byte //Key for Name Confidentiality 
	PrivateRSAkey *rsa.PrivateKey
}

// // The structure definition for a user record
// type File struct {
// 	Owner string //Owner
// 	OwnerSignature
// 	FileKeyA []byte //Key for Authentication
// 	FileKeyE []byte //Key for Encryption
// 	User
// }



// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error){
	var userdata User
	nilSalt := []byte(nil)
	blockSize := userlib.BlockSize
	hashSize := userlib.HashSize

	privateRSA, err := userlib.GenerateRSAKey()
	if err != nil{
		return &userdata, err
	}
	userdata.PrivateRSAkey = privateRSA
	userlib.KeystoreSet(username, privateRSA.PublicKey) //upload public key to KEYSERVER
	
	keyString := username + "/" + password //concatenating username and password, "/" marker to distinguish username+password attacks
	keyByte := []byte(keyString) //casting into byte array
	
	userConfidentialByte := userlib.PBKDF2Key(keyByte, nilSalt, blockSize)//obtain hash of confidential byte
	userConfidentialString := hex.EncodeToString(userConfidentialByte)//do NOT cast []byte to String... but you can cast String to []byte
	userinfoPath := "userinfo/" + userConfidentialString
	hmacPath := "userinfo/hmac/" + userConfidentialString

	userdata.Username = userConfidentialString

	userdata.KeyA = randomBytes(hashSize) //hashsize for key... hmac
	userdata.KeyE = randomBytes(blockSize) //blocksize for key... encryption
	userdata.KeyN = randomBytes(blockSize) //blocksize for key... encryption

	marshaledUserData, err := json.Marshal(userdata)
	if err != nil{
		return &userdata, err
	}
	byteUserData := []byte(marshaledUserData)
	userDataStringLen := len(byteUserData)

	//symmetric key generation
	userByte := []byte(username)
	passwordByte := []byte(password)
	userpassSymmetricKeyAuth := userlib.PBKDF2Key(passwordByte, userByte, hashSize)//obtain hash of confidential byte
	userpassSymmetricKeyEnc := userpassSymmetricKeyAuth[:blockSize]

	//Symmetric Encryption (not RSA)
	iv := randomBytes(blockSize) // []byte
	toAppend := make([]byte, userDataStringLen)
	encryptedUserData := append(iv, toAppend...)

	cipher := userlib.CFBEncrypter(userpassSymmetricKeyEnc, iv)
	cipher.XORKeyStream(encryptedUserData[blockSize:], byteUserData)
	userlib.DatastoreSet(userinfoPath, encryptedUserData) //Storing userdata to DATASTORESERVER

	//hmac signature
	toHash := encryptedUserData
	hasher := userlib.NewHMAC(userpassSymmetricKeyAuth)
	hasher.Write(toHash)
	hash := hasher.Sum(nil)
	userlib.DatastoreSet(hmacPath, hash) //Storing hmac to DATASTORESERVER

	return &userdata, err
}


// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error){
	var userdata User
	nilSalt := []byte(nil)
	blockSize := userlib.BlockSize
	hashSize := userlib.HashSize

	keyString := username + "/" + password //concatenating username and password, "/" marker to distinguish username+password attacks
	keyByte := []byte(keyString) //casting into byte array
	userConfidentialByte := userlib.PBKDF2Key(keyByte, nilSalt, blockSize)//obtain hash of confidential byte
	userConfidentialString := hex.EncodeToString(userConfidentialByte)//do NOT cast []byte to String... but you can cast String to []byte

	//obtain paths for encrypted userinfo and corresponding RSAsignature
	userinfoPath := "userinfo/" + userConfidentialString
	hmacPath := "userinfo/hmac/" + userConfidentialString
	
	//get the data at these paths
	gotUserinfo, ok1 := userlib.DatastoreGet(userinfoPath)
	gotHmac, ok2 := userlib.DatastoreGet(hmacPath)

	if (ok1 && ok2) == false{
		err = errors.New("Failure to load information. ")
		return &userdata, err
	}

	//symmetric key generation
	userByte := []byte(username)
	passwordByte := []byte(password)
	userpassSymmetricKeyAuth := userlib.PBKDF2Key(passwordByte, userByte, hashSize)//obtain hash of confidential byte
	userpassSymmetricKeyEnc := userpassSymmetricKeyAuth[:blockSize]

	//verification step
	//hmac signature
	toHash := gotUserinfo
	hasher := userlib.NewHMAC(userpassSymmetricKeyAuth)
	hasher.Write(toHash)
	hash := hasher.Sum(nil)

	if !(userlib.Equal(gotHmac, hash)){
		err = errors.New("Authentication for user hmac failed. ")
		return &userdata, err
	}

	//decryption step
	//iv had to have been appended somewhere
	//decrypted data in place -- replaced the encrypted data with decrypted data
	iv := gotUserinfo[:blockSize]
	cipher := userlib.CFBDecrypter(userpassSymmetricKeyEnc, iv)
	cipher.XORKeyStream(gotUserinfo[blockSize:], gotUserinfo[blockSize:])

	//unmarshal the data from []bytes to whatever it was before
	err = json.Unmarshal(gotUserinfo[blockSize:], &userdata)

	//recall that err was obtained from RSAverification
	return &userdata, err
}


// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	
	//REVISED:
	userAuthentication := userdata.KeyA
	userEncryption := userdata.KeyE
	userNameConfidential := userdata.KeyN
	//

	blockSize := userlib.BlockSize
	hashSize := userlib.HashSize
	dataLength := len(data)

	encryptedUsername := userdata.Username
	filenameByte := []byte(filename)

	//generate confidential filePath
	filenameEncryption := userlib.PBKDF2Key(filenameByte, userNameConfidential, blockSize)
	filenameEncryptionString := hex.EncodeToString(filenameEncryption)

	//REVISED:
	//use this for the user's personal layer
	userMasterFilePath := encryptedUsername + "/" + filenameEncryptionString
	userMasterFileMetadataPath := encryptedUsername + "/metadata/" + filenameEncryptionString

	masterfilePathByte := userlib.PBKDF2Key([]byte(userMasterFilePath), userNameConfidential, blockSize)
	masterMetadataPathByte := userlib.PBKDF2Key([]byte(userMasterFileMetadataPath), userNameConfidential, blockSize)
	masterFilePath := hex.EncodeToString(masterfilePathByte)
	masterMetadataPath := hex.EncodeToString(masterMetadataPathByte)
	//

	relativePathByte := randomBytes(blockSize)
	relativePathString := hex.EncodeToString(relativePathByte)

	//filePath: encrypted(username/filename/iv)
	//fileMetadataPath: encrypted(username/metadata/filename/iv)
	filePath := masterFilePath + "/" + relativePathString
	fileMetadataPath := masterMetadataPath + "/" + relativePathString


	//kEncryption can be derived from kAuthentication
	kAuthentication := randomBytes(hashSize)
	kEncryption := kAuthentication[:blockSize]

	//kAuthentication(32Bytes)||masterFilePath (16Bytes)||masterMetadataPath (16Bytes)
	path := append(masterfilePathByte, masterMetadataPathByte...)
	sharingSecret := append(kAuthentication, path...)

	//need to encrypt sharingSecret
	iv0 := randomBytes(blockSize) // []byte
	toAppend := make([]byte, len(sharingSecret))
	encryptedUserData := append(iv0, toAppend...)

	cipher := userlib.CFBEncrypter(userEncryption, iv0)
	cipher.XORKeyStream(encryptedUserData[blockSize:], sharingSecret)
	userlib.DatastoreSet(userMasterFilePath, encryptedUserData) //Storing userdata to DATASTORESERVER
	
	//need to hmac sign
	toHash0 := encryptedUserData
	hasher0 := userlib.NewHMAC(userAuthentication)
	hasher0.Write(toHash0)
	hash0 := hasher0.Sum(nil)
	userlib.DatastoreSet(userMasterFileMetadataPath, hash0)


	//because relativePathByte is already random and because IVs can be public,
	//we don't care about keeping it confidential. All we care about is making sure it is authentic
	//gives away nothing about username or filename
	userlib.DatastoreSet(masterFilePath, relativePathByte) //Storing IVs to masterfile

	//hmac signature of the contents in masterfile
	toHash := relativePathByte
	hasher := userlib.NewHMAC(kAuthentication)
	hasher.Write(toHash)
	hash := hasher.Sum(nil)
	userlib.DatastoreSet(masterMetadataPath, hash) //Storing masterfile hmac to DATASTORESERVER

	//Symmetric Encryption (not RSA)
	iv := relativePathByte // []byte
	encryptedData := make([]byte, blockSize + dataLength)

	cipher1 := userlib.CFBEncrypter(kEncryption, iv)
	cipher1.XORKeyStream(encryptedData[blockSize:], data)
	userlib.DatastoreSet(filePath, encryptedData) //Storing userdata to DATASTORESERVER

	//hmac signature of the actual file contents
	toHash2 := encryptedData
	hasher2 := userlib.NewHMAC(kAuthentication)
	hasher2.Write(toHash2)
	hash2 := hasher2.Sum(nil)
	userlib.DatastoreSet(fileMetadataPath, hash2) //Storing hmac to DATASTORESERVER
}


// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error){
	//REVISED:
	userAuthentication := userdata.KeyA
	userEncryption := userdata.KeyE
	userNameConfidential := userdata.KeyN
	//

	blockSize := userlib.BlockSize
	hashSize := userlib.HashSize
	dataLength := len(data)

	encryptedUsername := userdata.Username
	filenameByte := []byte(filename)

	//generate confidential filePath
	filenameEncryption := userlib.PBKDF2Key(filenameByte, userNameConfidential, blockSize)
	filenameEncryptionString := hex.EncodeToString(filenameEncryption)

	//REVISED:
	//use this for the user's personal layer
	userMasterFilePath := encryptedUsername + "/" + filenameEncryptionString
	userMasterFileMetadataPath := encryptedUsername + "/metadata/" + filenameEncryptionString



	//get the data at these paths
	gotUserinfo, ok1 := userlib.DatastoreGet(userMasterFilePath)
	gotHmac, ok2 := userlib.DatastoreGet(userMasterFileMetadataPath)

	if (ok1 && ok2) == false{
		err = errors.New("Failure to load userToMasterFile information in Append. ")
		return err
	}

	//verification step
	//hmac signature
	toHash0 := gotUserinfo
	hasher0 := userlib.NewHMAC(userAuthentication)
	hasher0.Write(toHash0)
	hash0 := hasher0.Sum(nil)

	if !(userlib.Equal(gotHmac, hash0)){
		err = errors.New("Authentication for userToMasterFile hmac failed in Append. ")
		return err
	}

	//decryption step
	//iv had to have been appended somewhere
	//decrypted data in place -- replaced the encrypted data with decrypted data
	iv0 := gotUserinfo[:blockSize]
	cipher := userlib.CFBDecrypter(userEncryption, iv0)
	cipher.XORKeyStream(gotUserinfo[blockSize:], gotUserinfo[blockSize:])


	kAuthentication := gotUserinfo[:hashSize]
	kEncryption := kAuthentication[:blockSize]
	paths := gotUserinfo[hashSize:]
	masterFilePath := paths[:blockSize]
	masterMetadataPath := paths[blockSize:]


	//relativePathByte for new fileLocation
	relativePathByte := randomBytes(blockSize)
	relativePathString := hex.EncodeToString(relativePathByte)

	//filePath: encrypted(username/filename/iv)
	//fileMetadataPath: encrypted(username/metadata/filename/iv)
	filePath := hex.EncodeToString(masterFilePath) + "/" + relativePathString
	fileMetadataPath := hex.EncodeToString(masterMetadataPath) + "/" + relativePathString


	//got the masterfile and authentication contents
	gotMasterfile, ok1 := userlib.DatastoreGet(hex.EncodeToString(masterFilePath))
	gotMasterMetadata, ok2 := userlib.DatastoreGet(hex.EncodeToString(masterMetadataPath))
	if (ok1 && ok2) == false{
		err = errors.New("Failure to load masterfile information in Append. ")
		return err
	}

	//verification step
	//hmac signature
	toHash := gotMasterfile
	hasher := userlib.NewHMAC(kEncryption)
	hasher.Write(toHash)
	hash := hasher.Sum(nil)

	if !(userlib.Equal(gotMasterMetadata, hash)){
		err = errors.New("Authentication for masterfile hmac failed in Append. ")
		return err
	}

	//no decryption for masterfile needed!
	//however, note that we will need to parse its contents in blockSize-increments when loading!
	newMasterfile := append(gotMasterfile, relativePathByte...)
	userlib.DatastoreSet(hex.EncodeToString(masterFilePath), newMasterfile) //Storing appended IVs masterfile

	//hmac signature of the contents of newMasterfile
	toHash1 := newMasterfile
	hasher1 := userlib.NewHMAC(kAuthentication)
	hasher1.Write(toHash1)
	hash1 := hasher1.Sum(nil)
	userlib.DatastoreSet(hex.EncodeToString(masterMetadataPath), hash1) //Storing masterfile hmac to DATASTORESERVER

	//Symmetric Encryption (not RSA)
	iv := relativePathByte // []byte
	encryptedData := make([]byte, blockSize + dataLength)

	cipher1 := userlib.CFBEncrypter(kEncryption, iv)
	cipher1.XORKeyStream(encryptedData[blockSize:], data)
	userlib.DatastoreSet(filePath, encryptedData) //Storing userdata to DATASTORESERVER

	//hmac signature of the actual file contents
	toHash2 := encryptedData
	hasher2 := userlib.NewHMAC(kAuthentication)
	hasher2.Write(toHash2)
	hash2 := hasher2.Sum(nil)
	userlib.DatastoreSet(fileMetadataPath, hash2) //Storing hmac to DATASTORESERVER

	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string)(data []byte, err error) {

	data = []byte(nil)

	userAuthentication := userdata.KeyA
	userEncryption := userdata.KeyE
	userNameConfidential := userdata.KeyN
	//

	blockSize := userlib.BlockSize
	hashSize := userlib.HashSize

	encryptedUsername := userdata.Username
	filenameByte := []byte(filename)

	//generate confidential filePath
	filenameEncryption := userlib.PBKDF2Key(filenameByte, userNameConfidential, blockSize)
	filenameEncryptionString := hex.EncodeToString(filenameEncryption)

	//REVISED:
	//use this for the user's personal layer
	userMasterFilePath := encryptedUsername + "/" + filenameEncryptionString
	userMasterFileMetadataPath := encryptedUsername + "/metadata/" + filenameEncryptionString

	//get the data at these paths
	gotUserinfo, ok1 := userlib.DatastoreGet(userMasterFilePath)
	gotHmac, ok2 := userlib.DatastoreGet(userMasterFileMetadataPath)


	if (ok1 && ok2) == false{
		err = errors.New("Failure to load userToMasterFile information in Load. ")
		return data, err
	}

	//verification step
	//hmac signature
	toHash0 := gotUserinfo
	hasher0 := userlib.NewHMAC(userAuthentication)
	hasher0.Write(toHash0)
	hash0 := hasher0.Sum(nil)

	if !(userlib.Equal(gotHmac, hash0)){
		err = errors.New("Authentication for userToMasterFile hmac failed in Load. ")
		return data, err
	}

	//decryption step
	//iv had to have been appended somewhere
	//decrypted data in place -- replaced the encrypted data with decrypted data
	iv0 := gotUserinfo[:blockSize]
	cipher := userlib.CFBDecrypter(userEncryption, iv0)
	cipher.XORKeyStream(gotUserinfo[blockSize:], gotUserinfo[blockSize:])

	fmt.Println("gotUserinfo decrypted")
	fmt.Println(hex.EncodeToString(gotUserinfo))
	fmt.Println()


	kAuthentication := gotUserinfo[:hashSize]
	kEncryption := kAuthentication[:blockSize]
	paths := gotUserinfo[hashSize:]
	masterFilePath := paths[:blockSize]
	masterMetadataPath := paths[blockSize:]


	fmt.Println("kAuthentication")
	fmt.Println(hex.EncodeToString(kAuthentication))
	fmt.Println()

	fmt.Println("kEncryption")
	fmt.Println(hex.EncodeToString(kEncryption))
	fmt.Println()



	fmt.Println("paths")
	fmt.Println(hex.EncodeToString(paths))
	fmt.Println()


	//got the masterfile and authentication contents
	gotMasterfile, ok1 := userlib.DatastoreGet(hex.EncodeToString(masterFilePath))
	gotMasterMetadata, ok2 := userlib.DatastoreGet(hex.EncodeToString(masterMetadataPath))
	
	fmt.Println("masterFilePath")
	fmt.Println(hex.EncodeToString(masterFilePath))
	fmt.Println()
	fmt.Println("masterMetadataPath")
	fmt.Println(hex.EncodeToString(masterMetadataPath))	
	fmt.Println()

	if (ok1 && ok2) == false{
		err = errors.New("Failure to load masterfile information in Load. ")
		return data, err
	}

	//verification step
	//hmac signature
	toHash := gotMasterfile
	hasher := userlib.NewHMAC(kEncryption)
	hasher.Write(toHash)
	hash := hasher.Sum(nil)

	if !(userlib.Equal(gotMasterMetadata, hash)){
		err = errors.New("Authentication for masterfile hmac failed in Load. ")
		return data, err
	}

	appendedContents := []byte(nil)

	//should be a multiple of blockSize
	masterfileLength := len(gotMasterfile)
	for i := 0; i < masterfileLength/blockSize; i++ {
		multiple1 := i * blockSize
		multiple2 := (i+1) * blockSize
		
		relativePathByte := gotMasterfile[multiple1:multiple2]
		relativePathString := hex.EncodeToString(relativePathByte)

		//filePath: username/filename/iv
		//fileMetadataPath: username/metadata/filename/iv
		filePath := hex.EncodeToString(masterFilePath) + "/" + relativePathString
		fileMetadataPath := hex.EncodeToString(masterMetadataPath) + "/" + relativePathString

		gotFilePart, ok1 := userlib.DatastoreGet(filePath)
		gotFileMetadataPart, ok2 := userlib.DatastoreGet(fileMetadataPath)
		if (ok1 && ok2) == false{
			err = errors.New("Failure to load filePart information. ")
			return data, err
		}

		//verification step
		//hmac signature
		toHash1 := gotFilePart
		hasher1 := userlib.NewHMAC(kEncryption)
		hasher1.Write(toHash1)
		hash1 := hasher1.Sum(nil)

		if !(userlib.Equal(gotFileMetadataPart, hash1)){
			err = errors.New("Authentication for filePart hmac failed. ")
			return data, err
		}

		//decryption step
		//iv had to have been appended somewhere
		//decrypted data in place -- replaced the encrypted data with decrypted data
		iv := gotFilePart[:blockSize]
		cipher := userlib.CFBDecrypter(kAuthentication, iv)
		cipher.XORKeyStream(gotFilePart[blockSize:], gotFilePart[blockSize:])

		appendedContents = append(appendedContents, gotFilePart...)
	}


	return appendedContents, err
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	//the location to this struct should be encrypted by the recipients public key

	Owner string//signed by Owner's private key, which can be decrypted only by public key
	OwnerSignature []byte //signed by Owner's private key, which can be decrypted only by public key
	
	Kauth []byte //authentication key
	Kenc []byte //authentication key

	MasterFile string //location of the masterfile STRING form
	MasterMetadata string //location of the masterfile metadata STRING form
}


// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string)(
	msgid string, err error){


	// userAuthentication := userdata.KeyA
	// userEncryption := userdata.KeyE
	// userNameConfidential := userdata.KeyN
	// //

	// blockSize := userlib.BlockSize
	// hashSize := userlib.HashSize

	// encryptedUsername := userdata.Username
	// filenameByte := []byte(filename)

	// //generate confidential filePath
	// filenameEncryption := userlib.PBKDF2Key(filenameByte, userNameConfidential, blockSize)
	// filenameEncryptionString := hex.EncodeToString(filenameEncryption)

	// //REVISED:
	// //use this for the user's personal layer
	// userMasterFilePath := encryptedUsername + "/" + filenameEncryptionString
	// userMasterFileMetadataPath := encryptedUsername + "/metadata/" + filenameEncryptionString

	// //get the data at these paths
	// gotUserinfo, ok1 := userlib.DatastoreGet(userMasterFilePath)
	// gotHmac, ok2 := userlib.DatastoreGet(userMasterFileMetadataPath)

	// if (ok1 && ok2) == false{
	// 	err = errors.New("Failure to load userToMasterFile information. ")
	// 	return err
	// }

	// //verification step
	// //hmac signature
	// toHash0 := gotUserinfo
	// hasher0 := userlib.NewHMAC(userAuthentication)
	// hasher0.Write(toHash0)
	// hash0 := hasher0.Sum(nil)

	// if hex.EncodeToString(gotHmac) != hex.EncodeToString(hash0){
	// 	err = errors.New("Authentication for userToMasterFile hmac failed. ")
	// 	return err
	// }

	// //decryption step
	// //iv had to have been appended somewhere
	// //decrypted data in place -- replaced the encrypted data with decrypted data
	// iv0 := gotUserinfo[:blockSize]
	// cipher := userlib.CFBDecrypter(userEncryption, iv0)
	// cipher.XORKeyStream(gotUserinfo[blockSize:], gotUserinfo[blockSize:])


	// kAuthentication := gotUserinfo[:hashSize]
	// kEncryption := kAuthentication[:blockSize]
	// paths := gotUserinfo[hashSize:]
	// masterFilePath := paths[:blockSize]
	// masterMetadataPath := paths[blockSize:]



	// //got the masterfile and authentication contents
	// gotMasterfile, ok1 := userlib.DatastoreGet(hex.EncodeToString(masterFilePath))
	// gotMasterMetadata, ok2 := userlib.DatastoreGet(hex.EncodeToString(masterMetadataPath))
	// if (ok1 && ok2) == false{
	// 	err = errors.New("Failure to load masterfile information. ")
	// 	return err
	// }

	// //verification step
	// //hmac signature
	// toHash := gotMasterfile
	// hasher := userlib.NewHMAC(kEncryption)
	// hasher.Write(toHash)
	// hash := hasher.Sum(nil)

	// if hex.EncodeToString(gotMasterMetadata) != hex.EncodeToString(hash){
	// 	err = errors.New("Authentication for masterfile hmac failed. ")
	// 	return err
	// }













	return 
}


// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {
	return nil
}

// Removes access for all others.  
func (userdata *User) RevokeFile(filename string) (err error){
	return 
}
