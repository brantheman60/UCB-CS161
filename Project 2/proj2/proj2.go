package proj2

// CS 161 Project 2 Spring 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
        var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}
// Helper function: String array to a []byte marshal
func StoM(S []string) ([]byte) {
	M, _ := json.Marshal(S)
	return M
}

// Helper Function: Get the FileKeys and FileInfo
func (userdata *User) GetFileStuff(filename string) (fk FileKeys, fi FileInfo, err error) {
	var filekeys FileKeys
	var fileinfo FileInfo

	// receive original fileinfo cipher from Datastore
	filekeys, ok := userdata.Files[filename]
	if !ok {
		return filekeys, fileinfo, errors.New("File " + filename + " does not exist")
	}
	fileinfo_cipher, _ := userlib.DatastoreGet(filekeys.FileInfoID)
	if len(fileinfo_cipher) < 16 {
		return filekeys, fileinfo, errors.New("Fileinfo is too short")
	}

	// break fileinfo into cipher and authentication tag
	hmac_index := len(fileinfo_cipher) - userlib.HashSize
	fileinfo_enc := fileinfo_cipher[:hmac_index]
	fileinfo_tag := fileinfo_cipher[hmac_index:]

	// check HMAC tag of fileinfo
	if len(filekeys.MKey) != 16 {
		return filekeys, fileinfo, errors.New("MAC Key doesn't work: Data is corrupted")
	}
	tag, err := userlib.HMACEval(filekeys.MKey, fileinfo_enc)
	if err != nil {
		return filekeys, fileinfo, errors.New("MAC Key doesn't work: Data is corrupted")
	}
	if !userlib.HMACEqual(fileinfo_tag, tag) {
		return filekeys, fileinfo, errors.New("HMAC doesn't match: Data is corrupted")
	}

	// get the marshaled FileInfo struct from userdata_encrypted using encryption key
	fileinfo_marshal := userlib.SymDec(filekeys.EKey, fileinfo_enc)
	// check if the unmarshalled FileInfo struct is valid
	err = json.Unmarshal(fileinfo_marshal, &fileinfo)
	if err != nil {
		return filekeys, fileinfo, errors.New("Encryption Key doesn't work: Unmarshal is corrupted")
	}

	return filekeys, fileinfo, err
}

// Helper Function: Store FileInfo in its proper location
func StoreFileInfo(filekeys FileKeys, fileinfo FileInfo) (err error){
	// Encrypt fileinfo w/ filekeys.EKey
	fileinfo_marshal, _ := json.Marshal(fileinfo)
	IV1 := userlib.RandomBytes(16)
	fileinfo_enc := userlib.SymEnc(filekeys.EKey, IV1, fileinfo_marshal)

	// HMAC fileinfo w/ filekeys.MKey
	if len(filekeys.MKey) != 16 { return errors.New("MAC Key doesn't work: Data is corrupted") }
	fileinfo_tag, err := userlib.HMACEval(filekeys.MKey, fileinfo_enc)
	if err != nil { return errors.New("MAC Key doesn't work: Data is corrupted") }

	// Store both into Datastore
	fileinfo_cipher := append(fileinfo_enc, fileinfo_tag...)
	userlib.DatastoreSet(filekeys.FileInfoID, fileinfo_cipher)

	return err
}

// The structure definition for a user record
// Only the user should be able to receive this information from Datastore
type User struct {
	// Non-encrypted Username (this is also the salt for Argon2Key)
	Username string
	// RSA private key (for encryption and digital certificates)
	RSAPrivKey userlib.PrivateKeyType
	// Datastore Location Key
	DSKey uuid.UUID
	// Symmetric encryption key
	EncryptKey []byte
	// HMAC key
	HMACKey []byte
	// maps strings (file names) to File structs
	Files map[string]FileKeys
}

// The necessary UUID and encryption+MAC keys to get file contents
type FileKeys struct {
	// UUID of FileInfo
	FileInfoID uuid.UUID
	// Encryption key for File
	EKey []byte
	// MAC key for File
	MKey []byte
}

// File data
type File struct {
	Data []byte
}

// File info (owner and total appends)
// other users may access this, so don't include info about file data or file name
type FileInfo struct {
	// RSA-encrypted
	Owner []byte
	// list of users who were directly shared file by Owner; non-encrypted
	SharedUsers []string
	// authentication tag of SharedUsers using Owner's HMAC key
	SharedUsers_tag []byte
	// total parts to this file (originally I used TotalAppends, but became hard to manage)
	TotalParts int
}


// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing
// hashes of common passwords downloaded from the internet.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	
	// prevent empty username or password
	if username == "" { return nil, errors.New("Username can't be empty") }
	if password == "" { return nil, errors.New("Password can't be empty") }

	// create deterministic salt from the username
	salt := []byte(username)

	// create RSA keys
	rsaPrivate, rsaPublic, err := userlib.DSKeyGen()

	// fill in User struct; use Argon2Key to deterministically create all the private keys
	userdata.Username = username
	userdata.RSAPrivKey = rsaPrivate
	dskey := userlib.Argon2Key([]byte(password), salt, 16)
	userdata.DSKey = bytesToUUID(dskey)
	userdata.EncryptKey = userlib.Argon2Key([]byte(password), salt, 16)
	userdata.HMACKey = userlib.Argon2Key([]byte(password), salt, 16)
	userdata.Files = make(map[string]FileKeys)

	// check RSAKey to make sure username isn't taken
	_, ok := userlib.KeystoreGet(username)
	if ok { return nil, errors.New("Username is already taken!")}

	// marshal the User struct
	userdata_marshal, _ := json.Marshal(userdata)
	// encrypt the User struct
	IV := userlib.RandomBytes(16) // 16-byte IV
	userdata_encrypted := userlib.SymEnc(userdata.EncryptKey, IV, userdata_marshal)
	// create HMAC from encrypted User struct
	userdata_tag, _ := userlib.HMACEval(userdata.HMACKey, userdata_encrypted)
	// append HMAC to encrypted User struct; now AES-CTR + HMAC
	userdata_cipher := append(userdata_encrypted, userdata_tag...)

	// store securely encrypted User in Datastore
	userlib.DatastoreSet(userdata.DSKey, userdata_cipher)

	// store public RSA key in Keystore
	userlib.KeystoreSet(username, rsaPublic)

	return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	
	// get salt again
	salt := []byte(username)

	// receive RSA public key from Keystore
	_, ok := userlib.KeystoreGet(username)
	if !ok { return nil, errors.New("User " + username + " not found or doesn't exist.") }

	// recreate private keys using deterministic Argon2Key
	dskey_tmp := userlib.Argon2Key([]byte(password), salt, 16) //since UUID is 16 bytes
	dskey := bytesToUUID(dskey_tmp)
	encryptkey := userlib.Argon2Key([]byte(password), salt, 16)
	hmackey := userlib.Argon2Key([]byte(password), salt, 16)

	// receive User ciphertext from Datastore
	userdata_cipher, ok := userlib.DatastoreGet(dskey)
	if !ok { return nil, errors.New(username + "'s password is incorrect.") }

	// get the actual userdata_encrypted and userdata_tag from the User ciphertext
	hmac_index := len(userdata_cipher) - userlib.HashSize
	userdata_encrypted := userdata_cipher[:hmac_index]
	userdata_tag := userdata_cipher[hmac_index:]
	
	// compare HMACs
	if len(hmackey) != 16 { return nil, errors.New("MAC Key doesn't work: Data is corrupted") }
	tag, err := userlib.HMACEval(hmackey, userdata_encrypted)
	if err != nil { return nil, errors.New("MAC Key doesn't work: Data is corrupted") }
	if !userlib.HMACEqual(userdata_tag, tag) {
		return nil, errors.New("HMAC doesn't match: Data is corrupted")
	}

	// get the marshaled User struct from userdata_encrypted using encryptkey
	userdata_marshal := userlib.SymDec(encryptkey, userdata_encrypted)
	// check if the unmarshalled User struct is valid
	err = json.Unmarshal(userdata_marshal, &userdata)
	if err != nil { return nil, errors.New("Encryption Key doesn't work: Unmarshal is corrupted") }
	
	return &userdata, err
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	// randomly create UUID (Datastore Key) for File and FileInfo
	fileinfo_ID := uuid.New() //random
	newString := fileinfo_ID.String() + string(1) // deterministic; use 1 b/c file only has 1 part
	newString_index := len(newString) - 16 // only use the last 16 bytes of newString
	file_ID, _ := uuid.FromBytes([]byte(newString)[newString_index:])

	// randomly create 16-byte encryption and MAC symmetric keys for file
	file_ekey := userlib.RandomBytes(16)
	file_mkey := userlib.RandomBytes(16)
	
	// create FileKeys struct
	var filekeys FileKeys
	filekeys.FileInfoID = fileinfo_ID
	filekeys.EKey = file_ekey
	filekeys.MKey = file_mkey

	// create File struct
	var file File
	file.Data = data

	// create FileInfo struct
	var fileinfo FileInfo
	rsaPublic, _ := userlib.KeystoreGet(userdata.Username)
	rsaPublic.KeyType = "PKE" // rsaPublic must be PKE type
	username_enc, _ := userlib.PKEEnc(rsaPublic, []byte(userdata.Username))

	fileinfo.Owner = username_enc // RSA-encrypted owner's username
	blank_arr := []string{}
	fileinfo.SharedUsers = blank_arr
	fileinfo.SharedUsers_tag, _ = userlib.HMACEval(userdata.HMACKey, StoM(blank_arr))
	fileinfo.TotalParts = 1 // original file, so no appends yet

	// encrypt the File and FileInfo
	file_marshal, _ := json.Marshal(file)
	fileinfo_marshal, _ := json.Marshal(fileinfo)
	IV1 := userlib.RandomBytes(16)
	IV2 := userlib.RandomBytes(16)
	file_enc := userlib.SymEnc(file_ekey, IV1, file_marshal)
	fileinfo_enc := userlib.SymEnc(file_ekey, IV2, fileinfo_marshal)

	// create and append HMAC to the File and FileInfo
	file_tag, _ := userlib.HMACEval(file_mkey, file_enc)
	fileinfo_tag, _ := userlib.HMACEval(file_mkey, fileinfo_enc)
	file_cipher := append(file_enc, file_tag...)
	fileinfo_cipher := append(fileinfo_enc, fileinfo_tag...)

	// store the File and FileInfo in Datastore
	userlib.DatastoreSet(file_ID, file_cipher)
	userlib.DatastoreSet(fileinfo_ID, fileinfo_cipher)

	// update userdata's Files map
	userdata.Files[filename] = filekeys

	// add updated userdata to Datastore; taken directly from InitUser
	userdata_marshal, _ := json.Marshal(userdata)
	IV := userlib.RandomBytes(16) // 16-byte IV
	userdata_encrypted := userlib.SymEnc(userdata.EncryptKey, IV, userdata_marshal)
	userdata_tag, _ := userlib.HMACEval(userdata.HMACKey, userdata_encrypted)
	userdata_cipher := append(userdata_encrypted, userdata_tag...)
	userlib.DatastoreSet(userdata.DSKey, userdata_cipher)
	
	return
}


// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	// Load in fileinfo and filekeys
	var fileinfo FileInfo
	var filekeys FileKeys
	filekeys, fileinfo, err = userdata.GetFileStuff(filename)
	if err != nil { return err }

	// create new File struct
	var file File
	file.Data = data

	// marshal, encrypt, and HMAC the new file
	file_marshal, _ := json.Marshal(file)
	IV := userlib.RandomBytes(16)
	file_enc := userlib.SymEnc(filekeys.EKey, IV, file_marshal)
	file_tag, err := userlib.HMACEval(filekeys.MKey, file_enc)
	if err != nil { return errors.New("MAC Key doesn't work: Data is corrupted") }
	file_cipher := append(file_enc, file_tag...)

	// update the fileinfo (TotalParts has increased!)
	fileinfo.TotalParts += 1

	// store new file (to be appended) in Datastore
	// add TotalParts to create a new, deterministic UUID for the file's location
	newString := filekeys.FileInfoID.String() + string(fileinfo.TotalParts)
	newString_index := len(newString) - 16 // only use the last 16 bytes of newString
	newfile_ID, _ := uuid.FromBytes([]byte(newString)[newString_index:])
	userlib.DatastoreSet(newfile_ID, file_cipher)

	/** DELETE ME **/
	// println("/**")
	// aaa, _ := userdata.LoadFile(filename)
	// println("\n**/")
	// print("Original Data: ")
	// println(string(aaa))

	// Store fileinfo back into Datastore
	err = StoreFileInfo(filekeys, fileinfo)
	if err != nil { return err }

	return err
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	var fulldata []byte

	// Load in fileinfo and filekeys
	var fileinfo FileInfo
	var filekeys FileKeys
	filekeys, fileinfo, err = userdata.GetFileStuff(filename)
	if err != nil { return nil, err }

	// for the original file and each append...
	for i := 1; i <= fileinfo.TotalParts; i++ {
		// the current file, starting from the original
		var file File
		
		// recompute deterministic UUID for the file's location; copied from AppendFile
		newString := filekeys.FileInfoID.String() + string(i)
		newString_index := len(newString) - 16 // only use the last 16 bytes of newString
		file_ID, _ := uuid.FromBytes([]byte(newString)[newString_index:])

		// receive file from Datastore at the newly computed file_ID
		file_cipher, _ := userlib.DatastoreGet(file_ID)

		// retrieve HMAC
		hmac_index := len(file_cipher) - userlib.HashSize
		file_encrypted := file_cipher[:hmac_index]
		file_tag := file_cipher[hmac_index:]
		// check HMAC
		if len(filekeys.MKey) != 16 { return nil, errors.New("MAC Key doesn't work: Data is corrupted")}
		tag, err := userlib.HMACEval(filekeys.MKey, file_encrypted)
		if err != nil { return nil, errors.New("MAC Key doesn't work: Data is corrupted") }
		if !userlib.HMACEqual(file_tag, tag) {
			return nil, errors.New("HMAC doesn't match: Data is corrupted")
		}

		// decrypt and unmarshal file
		file_marshal := userlib.SymDec(filekeys.EKey, file_encrypted)
		err = json.Unmarshal(file_marshal, &file)
		if err != nil { return nil, errors.New("Encryption Key doesn't work: Unmarshal is corrupted") }

		// append the file's data to fulldata
		fulldata = append(fulldata, file.Data...)
	}

	return fulldata, err
}




// the sharing record that contains the file info location and required keys
type Record struct {
	RSASignature []byte // RSA-signed EKeyMKey
	FileInfoID uuid.UUID // includes the owner and total appends
	EKeyMKey []byte // append(encryption key | authentication key), then RSA encrypted
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {
	
	// check that recipient exists
	if userdata.Username == recipient {
		return "", errors.New("Recipient " + recipient + " is yourself, dummy!")
	}
	recipient_rsapub, ok := userlib.KeystoreGet(recipient)
	if !ok { return "", errors.New("Recipient " + recipient + " not found or doesn't exist.") }

	// Load in fileinfo and filekeys
	var fileinfo FileInfo
	var filekeys FileKeys
	filekeys, fileinfo, err = userdata.GetFileStuff(filename)
	if err != nil { return "", err }

	// append decryption key + authentication key
	ekey_mkey := append(filekeys.EKey, filekeys.MKey...)

	// encrypt ekey_mkey with recipient's public key
	ekey_mkey_marshal, _ := json.Marshal(ekey_mkey)
	recipient_rsapub.KeyType = "PKE" // recipient_rsapub must be PKE Key
	ekey_mkey_enc, err := userlib.PKEEnc(recipient_rsapub, ekey_mkey_marshal)
	if err != nil { return "", errors.New("Couldn't RSA encrypt ekey_mkey") }
	
	// add RSA signature to ekey_mkey_enc
	ekey_mkey_signed, err := userlib.DSSign(userdata.RSAPrivKey, ekey_mkey_enc)
	if err != nil { return "", errors.New("Couldn't create RSA signature") }

	// create Record struct
	var record Record
	record.RSASignature = ekey_mkey_signed
	record.FileInfoID = filekeys.FileInfoID
	record.EKeyMKey = ekey_mkey_enc

	// randomly create UUID for Record struct, and store in Datastore
	recordID := uuid.New()
	record_marshal, err := json.Marshal(record)
	userlib.DatastoreSet(recordID, record_marshal)

	// If you are the Owner, update fileinfo.SharedUsers and store it back
	rsaPrivate := userdata.RSAPrivKey
	rsaPrivate.KeyType = "PKE" // rsaPrivate must be PKE type
	owner, _ := userlib.PKEDec(rsaPrivate, []byte(fileinfo.Owner))
	if string(owner) == userdata.Username {
		// You are the original file owner
		
		// append recipient to fileinfo.SharedUsers
		users_arr := fileinfo.SharedUsers
		users_tag, _ := userlib.HMACEval(userdata.HMACKey, StoM(users_arr))
		if !userlib.HMACEqual(users_tag, fileinfo.SharedUsers_tag) {
			return "", errors.New("SharedUsers was corrupted!!!")
		}
		users_arr = append(users_arr, []string{recipient}...)
		users_tag, _ = userlib.HMACEval(userdata.HMACKey, StoM(users_arr))
		fileinfo.SharedUsers = users_arr
		fileinfo.SharedUsers_tag = users_tag

		// Store fileinfo back into Datastore
		err = StoreFileInfo(filekeys, fileinfo)
		if err != nil { return "", err }
	}

	return recordID.String(), err
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	
	// receive sender's public RSA key
	sender_rsapub, ok := userlib.KeystoreGet(sender)
	if !ok { return errors.New("Sender " + sender + " not found or doesn't exist.") }

	// ensure filename isn't already used
	_, ok = userdata.Files[filename]
	if ok { return errors.New("Filename " + filename + " is already taken.") }
	
	// receive Record struct from Datastore at magic_string
	recordID, err := uuid.Parse(magic_string)
	record_marshal, ok := userlib.DatastoreGet(recordID)
	if !ok { return errors.New("Could not get shared file.") }
	
	// unmarshal Record
	var record Record
	err = json.Unmarshal(record_marshal, &record)
	if err != nil { return errors.New("Unmarshaling Record failed") }

	// verify the RSA signature
	err = userlib.DSVerify(sender_rsapub, record.EKeyMKey, record.RSASignature)
	if err != nil { return errors.New("RSA Verification of Record failed") }

	// decrypt EKeyMKey using own RSA private key
	rsakey := userdata.RSAPrivKey
	rsakey.KeyType = "PKE" // rsakey must be PKE Key
	ekey_mkey_marshal, err := userlib.PKEDec(rsakey, record.EKeyMKey)
	if err != nil { return errors.New("Decrypting ekey_mkey_marshal failed") }
	
	// unmarshal ekey_mkey
	var ekey_mkey []byte
	err = json.Unmarshal(ekey_mkey_marshal, &ekey_mkey)
	if err != nil { return errors.New("Unmarshaling Keys failed") }

	// retrive EKey and MKey
	mkey_index := len(ekey_mkey) - 16 // last 16 bytes is MKey
	ekey := ekey_mkey[:mkey_index]
	mkey := ekey_mkey[mkey_index:]

	// create filekeys and add it to own userdata.Files
	var filekeys FileKeys
	filekeys.FileInfoID = record.FileInfoID
	filekeys.EKey = ekey
	filekeys.MKey = mkey
	userdata.Files[filename] = filekeys

	// update userdata in DataStore
	userdata_marshal, _ := json.Marshal(userdata)
	IV := userlib.RandomBytes(16)
	// Remember to Enc and HMAC it first!
	userdata_enc := userlib.SymEnc(ekey, IV, userdata_marshal)
	if len(mkey) != 16 { return errors.New("MAC Key doesn't work: Data is corrupted") }
	userdata_tag, err := userlib.HMACEval(mkey, userdata_enc)
	if err != nil { return errors.New("MAC Key doesn't work: Data is corrupted") }
	userdata_cipher := append(userdata_enc, userdata_tag...)
	userlib.DatastoreSet(userdata.DSKey, userdata_cipher)
	
	return err
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	
	/** Load in fileinfo and filekeys **/
	var fileinfo FileInfo
	var filekeys FileKeys
	filekeys, fileinfo, err = userdata.GetFileStuff(filename)
	if err != nil { return err }

	
	/** only the original owner can revoke! verify user matches FileInfo.Owner;
		inverse of what was done in StoreFile **/
	rsaPrivate := userdata.RSAPrivKey
	rsaPrivate.KeyType = "PKE" // rsaPrivate must be PKE type
	owner, _ := userlib.PKEDec(rsaPrivate, []byte(fileinfo.Owner))
	if string(owner) != userdata.Username {
		return errors.New("You are not the original file owner")
	}

	/** only revoke a user who's been shared with by Owner **/
	// Does user exist?
	_, ok := userlib.KeystoreGet(target_username)
	if !ok { return errors.New("User " + target_username + " not found or doesn't exist.") }
	
	// Is user in fileinfo.ShareUsers?
	users_arr := fileinfo.SharedUsers
	users_tag, _ := userlib.HMACEval(userdata.HMACKey, StoM(users_arr))
	if !userlib.HMACEqual(users_tag, fileinfo.SharedUsers_tag) {
		return errors.New("SharedUsers was corrupted")
	}

	was_shared := false
	var user_index int
	for i := 0; i < len(users_arr); i++ {
		if users_arr[i] == target_username {
			user_index = i
			was_shared = true
		}
	}
	if !was_shared { return errors.New("User " + target_username + " wasn't shared this.") }

	
	/** combine the file data from Datastore, including all the appends, into 1 file
		Delete the old file, and store the new file **/
	data, err := userdata.LoadFile(filename)
	if err != nil { return errors.New("Owner can't load the file data") }
	userlib.DatastoreDelete(userdata.DSKey)
	userdata.StoreFile(filename, data)


	/** Remove target_username from fileinfo.SharedUsers **/
	copy(users_arr[user_index:], users_arr[user_index+1:]) //shift arr[i+1:] left by 1
	users_arr[len(users_arr)-1] = "" //erase last element
	users_arr = users_arr[:len(users_arr)-1] //truncate slice
	
	/** Change fileinfo and store it back into Datastore **/
	fileinfo.SharedUsers = users_arr
	fileinfo.SharedUsers_tag, _ = userlib.HMACEval(userdata.HMACKey, StoM(users_arr))
	
	err = StoreFileInfo(filekeys, fileinfo)
	if err != nil { return err }


	/** StoreFile again, and share file w/ everyone in SharedUsers **/
	userdata.StoreFile(filename, data)
	for i := 0; i < len(users_arr); i++ {
		userdata.ShareFile(filename, users_arr[i])
	}


	return err
}
