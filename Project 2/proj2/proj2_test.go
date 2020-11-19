package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"testing"
	"reflect"
	"github.com/cs161-staff/userlib"
	_ "encoding/json"
	_ "encoding/hex"
	_ "github.com/google/uuid"
	_ "strings"
	_ "errors"
	_ "strconv"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}


func TestInit(t *testing.T) {
	clear()
	//t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	// Create users Alice and Bob (who happen to both choose fubar as password)
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize alice", err)
		return
	}
	u2, err := InitUser("bob", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize bob", err)
		return
	}

	// Initialize Alice #2 and #3; should fail
	_, err = InitUser("alice", "password123")
	if err == nil {
		t.Error("Allowed alice to be initialized twice", err)
		return
	}

	// Now get Alice and Bob back
	uget, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user alice", err)
		return
	}
	u2get, err := GetUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to get user bob", err)
		return
	}

	// can't verify each field in userdata b/c autograder has different proj2.go implementation

	// Implementation specific: Compare the userdatas using my utoa() function
	// if utoa(u) != utoa(uget) {
	// 	t.Error("Alice's userdata was changed at some time")
	// 	return
	// }
	// if utoa(u2) != utoa(u2get) {
	// 	t.Error("Bob's userdata was changed at some time")
	// 	return
	// }

	_, _, _, _ = u, uget, u2, u2get
	
}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

}

///// My Own Tests /////

func TestAppend(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	// Create test file
	filename := "testfile"
	data := []byte("This is a test file content")
	//newdata := []byte("This is a test file content") //!!!
	newdata := []byte("AND MORE")
	newnewdata := []byte("THEN DONE")

	// Store File
	u.StoreFile(filename, data)

	// Load File
	dataload, err := u.LoadFile(filename)
	if err != nil {
		t.Error("Loading file failed", err)
	}
	if !reflect.DeepEqual(data, dataload) {
		t.Error("Downloaded file is not the same")
	}

	// (1) Append File, then Load again
	u.AppendFile(filename, newdata) // append the same data
	dataload, err = u.LoadFile(filename)
	if err != nil {
		t.Error("Loading file failed", err)
	}
	data = append(data, newdata...)
	if !reflect.DeepEqual(data, dataload) {
		t.Error("Downloaded file is not the same")
	}

	// (2) Append File, then Load again
	u.AppendFile(filename, newnewdata) // append the same data
	dataload, err = u.LoadFile(filename)
	if err != nil {
		t.Error("Loading file failed", err)
	}
	data = append(data, newnewdata...)
	if !reflect.DeepEqual(data, dataload) {
		t.Error("Downloaded file is not the same")
	}
}

func TestAppend2(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	// Create test file (blank name and data)
	filename := ""
	data := []byte("hi")
	newdata := []byte("Now, file is no longer blank")

	// Store File
	u.StoreFile(filename, data)

	// Append File, then Load
	u.AppendFile(filename, newdata) // append the same data
	dataload, err := u.LoadFile(filename)
	if err != nil {
		t.Error("Loading file failed", err)
	}
	data = append(data, newdata...)
	if !reflect.DeepEqual(data, dataload) {
		t.Error("Downloaded file is not the same")
	}
}

func TestRevoke(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
	}
	u2, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize bob", err)
	}
	u3, err := InitUser("chris", "password")
	if err != nil {
		t.Error("Failed to initialize chris", err)
	}

	// Alice stores a file and shares w/ Bob
	filename := "alice_file"
	data := []byte("This is a test")
	newdata := []byte("AND THIS IS APPENDED")
	u.StoreFile(filename, data)

	magic_string, err := u.ShareFile(filename, "bob")
	u2.ReceiveFile(filename, "alice", magic_string)

	// Can Bob revoke from Alice? No!!!
	err = u2.RevokeFile(filename, "alice")
	if err == nil {
		t.Error("Bob revoked Alice's own file")
	}

	// Can Bob's RevokeFile() harm Alice? No!!!
	data, err = u.LoadFile(filename)
	if err != nil {
		t.Error("Bob prevented Alice from opening the file", err)
	}


	// Alice revokes Bob's access
	err = u.RevokeFile(filename, "bob")
	if err != nil {
		t.Error("RevokeFile failed", err)
	}

	// Check that Bob cannot revoke info again
	err = u2.RevokeFile(filename, "bob")
	if err == nil {
		t.Error("RevokeFile did not revoke Bob's access")
	}

	// Check that Alice didn't revoke herself
	data, err = u.LoadFile(filename)
	if err != nil {
		t.Error("RevokeFile voked Bob's access", err)
	}

	// Check that Alice cannot revoke Chris
	err = u.RevokeFile(filename, "chris")
	if err == nil {
		t.Error("Alice somehow revoked Chris")
		t.Log(u3)
	}


	// Now ensure that Bob cannot see future updates to file
	u.AppendFile(filename, newdata) // append the same data
	
	// Alice gets right data...
	dataload, err := u.LoadFile(filename)
	if err != nil {
		t.Error("Loading file failed", err)
	}
	data = append(data, newdata...)
	if !reflect.DeepEqual(data, dataload) {
		t.Error("Downloaded file is not the same")
	}
	
	// ...but Bob doesn't
	data2load, err := u2.LoadFile(filename)
	if err != nil { // for Bob, it's okay if he loads the original file
		t.Error("Loading file failed", err)
	}
	if reflect.DeepEqual(data, data2load) {
		t.Error("Bob was able to see the appended data")
	}

}

func TestReceive2(t *testing.T) {
	clear()
	// Create Alice and Bob
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to create Alice", err)
	}
	u2, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to create Bob", err)
	}

	// Alice stores a file
	filename := "alice's amazing file"
	data := []byte("Have a wonderful day")
	u.StoreFile(filename, data)

	// Did the file change?
	dataload, err := u.LoadFile(filename)
	if err != nil {
		t.Error("Failed to reload data", err)
	}
	if !reflect.DeepEqual(data, dataload) {
		t.Error("Downloaded file is different")
	}

	// Alice shares the file w/ Bob
	magic_string, err := u.ShareFile(filename, "bob")
	if err != nil {
		t.Error("ShareFile() failed", err)
	}

	// Bob receives the file
	bobfilename := "bob's brilliant file"
	u2.ReceiveFile(bobfilename, "alice", magic_string)
	data2load, err := u2.LoadFile(bobfilename)
	if err != nil {
		t.Error("Failed to receive shared file", err)
		return
	}
	if !reflect.DeepEqual(data, data2load) {
		t.Error("Downloaded file is different")
	}
}

func TestGet(t *testing.T) {
	clear()

	// Create Alice
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}

	// Now get Alice back twice
	uget1, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user alice", err)
		return
	}
	uget2, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user alice", err)
		return
	}

	// Prepare the files
	filename := "alicefile"
	data := []byte("testing123")

	// when U1 stores a file, U2 should load it
	uget1.StoreFile(filename, data)
	dataload, err := uget2.LoadFile(filename)
	if !reflect.DeepEqual(data, dataload) {
		t.Error("Could not store and load with different instances", err)
	}

	// when U1 appends a file, U2 should be able to load it
	newdata := []byte("APPENDED CONTENT")
	err = uget1.AppendFile(filename, newdata)
	if err != nil {
		t.Error("Failed to append file", err)
		return
	}
	data = append(data, newdata...)

	dataload, err = uget2.LoadFile(filename)
	if !reflect.DeepEqual(data, dataload) || err != nil{
		t.Error("Could not append and load with different instances", err)
	}

	// when U1 receives a file, U2 should be able to load it
	u3, err := InitUser("chris", "password123")
	if err != nil {
		t.Error("Failed to initialize chris", err)
		return
	}
	u3.StoreFile("f", []byte("test content"))
	magic_string, err := u3.ShareFile("f", "alice")
	if err != nil {
		t.Error("Failed to share file", err)
		return
	}

	err = uget1.ReceiveFile("alice_file", "chris", magic_string)
	if err != nil {
		t.Error("Failed to receive file", err)
		return
	}
	dataload, err = uget2.LoadFile(filename)
	if !reflect.DeepEqual(dataload, []byte("test content")) || err != nil{
		t.Error("Could not append and load with different instances", err)
	}

	_, _, _ = u, uget1, uget2
	
}

func TestGeneral(t *testing.T) {
	clear()

	///// INITUSER /////

	// no blank usernames or passwords!
	_, err := InitUser("", "fubar")
	if err == nil {
		t.Error("Allowed blank username")
		return
	}
	_, err = InitUser("alice", "")
	if err == nil {
		t.Error("Allowed blank password")
		return
	}

	// create Alice, Bob, and Chris
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize Alice", err)
		return
	}
	u2, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize Bob", err)
		return
	}
	u3, err := InitUser("chris", "fubar")
	if err != nil {
		t.Error("Failed to initialize Chris", err)
		return
	}

	// can't initialize user twice
	_, err = InitUser("alice", "a random password")
	if err == nil {
		t.Error("Allowed same initialization")
		return
	}

	///// GETUSER /////

	// get shouldn't work if using wrong username or password
	_, err = GetUser("wronguser", "fubar")
	if err == nil {
		t.Error("Wrong username was allowed")
		return
	}
	_, err = GetUser("alice", "wrongpassword")
	if err == nil {
		t.Error("Wrong password was allowed")
		return
	}
	_, err = GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get Alice", err)
		return
	}

	///// STOREFILE/LOADFILE /////

	// must allow storage of blank files
	alice_filename := ""
	alice_data := []byte("Filename is blank")
	alice_filename2 := "Data is blank"
	alice_data2 := []byte("")
	u.StoreFile(alice_filename, alice_data)
	u.StoreFile(alice_filename2, alice_data2)

	alice_dataload, err := u.LoadFile(alice_filename)
	if !reflect.DeepEqual(alice_data, alice_dataload) || err != nil {
		t.Error("Couldn't store and load blank filename", err)
		return
	}
	alice_dataload2, err := u.LoadFile(alice_filename2)
	
	// reflect.DeepEqual can't handle blanks
	// if !reflect.DeepEqual(data2, dataload2) || err != nil {
	if string(alice_data2) != string(alice_dataload2) || err != nil {
		t.Error("Couldn't store and load blank data", err)
		return
	}

	// set second file to first file's data. Check that both have "Filename is blank"
	alice_data2 = alice_data
	u.StoreFile(alice_filename2, alice_data2)
	alice_dataload, err = u.LoadFile(alice_filename)
	if !reflect.DeepEqual(alice_data, alice_dataload) || err != nil {
		t.Error("First file was unexpectedly changed", err)
		return
	}
	alice_dataload2, err = u.LoadFile(alice_filename2)
	if !reflect.DeepEqual(alice_data2, alice_dataload2) || err != nil {
		t.Error("Second file was not changed", err)
		return
	}

	// ensure Alice cannot load files that don't exist
	_, err = u.LoadFile("not a real file")
	if err == nil {
		t.Error("Alice accessed file that doesn't exist")
		return
	}
	_, err = u.LoadFile("alice")
	if err == nil {
		t.Error("Alice accessed file that doesn't exist")
		return
	}

	// ensure Bob cannot access either file
	_, err = u2.LoadFile(alice_filename)
	if err == nil {
		t.Error("Bob accessed unshared file")
		return
	}
	_, err = u2.LoadFile(alice_filename2)
	if err == nil {
		t.Error("Bob accessed unshared file")
		return
	}

	///// APPENDFILE /////

	// append to the first file; file doesn't exist
	newdata := []byte("APPENDED CONTENT")
	err = u.AppendFile("fakefile", newdata)
	if err == nil {
		t.Error("Appended to file that doesn't exist")
		return
	}
	alice_dataload, err = u.LoadFile(alice_filename)
	if !reflect.DeepEqual(alice_data, alice_dataload) || err != nil {
		t.Error("False AppendFile changed original file", err)
		return
	}

	// append to the first file for real
	err = u.AppendFile(alice_filename, newdata)
	if err != nil {
		t.Error("Failed to append file", err)
		return
	}
	alice_data = append(alice_data, newdata...)
	alice_dataload, err = u.LoadFile(alice_filename)
	if !reflect.DeepEqual(alice_data, alice_dataload) || err != nil {
		t.Error("Incorrectly appended file", err)
		return
	}

	///// SHAREFILE /////

	// Alice shares first file with Bob; wrong user
	_, err = u.ShareFile(alice_filename, "jonathan")
	if err == nil {
		t.Error("Shared File with person who doesn't exist", err)
		return
	}
	
	// Alice shares first file with Bob for real
	magic_string, err := u.ShareFile(alice_filename, "bob")
	if err != nil {
		t.Error("Failed to share file with Bob", err)
		return
	}

	///// RECIEVEFILE /////

	// Bob receives Alice's file; must be correct location
	bob_filename := "bob's filename"
	err = u2.ReceiveFile(bob_filename, "alice", magic_string+string("garbage"))
	if err == nil {
		t.Error("Received file at wrong location")
		return
	}
	_, err = u2.LoadFile(bob_filename)
	if err == nil {
		t.Error("Bob created a file he shouldn't have created")
		return
	}

	// Bob receives Alice's file; must be correct user
	err = u2.ReceiveFile(bob_filename, "bob", magic_string)
	if err == nil {
		t.Error("Received file from wrong person")
		return
	}
	err = u2.ReceiveFile(bob_filename, "chris", magic_string)
	if err == nil {
		t.Error("Received file from wrong person")
		return
	}
	err = u2.ReceiveFile(bob_filename, "jonathan", magic_string)
	if err == nil {
		t.Error("Received file from wrong person")
		return
	}
	_, err = u2.LoadFile(bob_filename)
	if err == nil {
		t.Error("Bob created a file he shouldn't have created")
		return
	}

	// Bob receives Alice's first file for real
	err = u2.ReceiveFile(bob_filename, "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive file")
		return
	}
	bob_data, err := u2.LoadFile(bob_filename)
	if !reflect.DeepEqual(alice_data, bob_data) || err != nil {
		t.Error("Failed to load correct file content")
		return
	}

	// Alice shares second file with Bob
	magic_string, err = u.ShareFile(alice_filename2, "bob")
	if err != nil {
		t.Error("Failed to share file with Bob", err)
		return
	}

	// Bob receives second file; uses same filename
	err = u2.ReceiveFile(bob_filename, "alice", magic_string)
	if err == nil {
		t.Error("Wrote over file w/ same filename")
		return
	}

	// Bob receives second file for real
	bob_filename2 := "bob's second filename"
	err = u2.ReceiveFile(bob_filename2, "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive file")
		return
	}
	bob_data2, err := u2.LoadFile(bob_filename2)
	if !reflect.DeepEqual(alice_data2, bob_data2) || err != nil {
		t.Error("Failed to load correct file content")
		return
	}

	///// SHAREFILE/RECEIVEFILE (Bob/Chris) /////

	// Bob shares first file with Chris
	magic_string, err = u2.ShareFile(bob_filename, "chris")
	if err != nil {
		t.Error("Failed to share file with Chris", err)
		return
	}

	// Chris recieves file; wrong user
	chris_filename := "chris's filename"
	err = u3.ReceiveFile(chris_filename, "alice", magic_string)
	if err == nil {
		t.Error("Received file from wrong person")
		return
	}

	// Chris recieves file for real
	err = u3.ReceiveFile(chris_filename, "bob", magic_string)
	if err != nil {
		t.Error("Failed to receive file", err)
		return
	}
	chris_data, err := u3.LoadFile(chris_filename)
	if !reflect.DeepEqual(alice_data, chris_data) || err != nil {
		t.Error("Failed to load correct file content")
		return
	}

	///// APPENDFILE (Chris) /////
	// Chris appends to the first file
	newnewdata := []byte("WITH EVEN MORE CONTENT")
	chris_data = append(chris_data, newnewdata...)
	err = u3.AppendFile(chris_filename, newnewdata)
	if err != nil {
		t.Error("Failed to append file", err)
		return
	}

	// Ensure everyone gets the same updated file
	bob_data, err = u2.LoadFile(bob_filename)
	if !reflect.DeepEqual(chris_data, bob_data) || err != nil {
		t.Error("Append was not shared with everyone", err)
		return
	}
	alice_data, err = u.LoadFile(alice_filename)
	if !reflect.DeepEqual(chris_data, alice_data) || err != nil {
		t.Error("Append was not shared with everyone", err)
		return
	}

	///// REVOKEFILE /////
	// Alice revokes Bob's access; wrong username
	err = u.RevokeFile(alice_filename, "jonathan")
	if err == nil {
		t.Error("Revoked a user that doesn't exist")
		return
	}
	err = u.RevokeFile(alice_filename, "alice")
	if err == nil {
		t.Error("Cannot revoke yourself")
		return
	}

	// Alice revokes Bob's access; wrong filename
	err = u.RevokeFile("fakefile", "bob")
	if err == nil {
		t.Error("Revoked a user from a fake file")
		return
	}

	// Alice revokes Bob's access for real
	err = u.RevokeFile(alice_filename, "bob")
	if err != nil {
		t.Error("Failed to revoke file", err)
		return
	}

	// Replace the file content; only shared users will be updated
	alice_data = []byte("Goodbye, World")
	u.StoreFile(alice_filename, alice_data)

	// Check that Bob and Chris do not get the update
	bob_data, _ = u2.LoadFile(bob_filename)
	if reflect.DeepEqual(alice_data, bob_data) {
		t.Error("Revoked user got the file update")
		return
	}
	chris_data, _ = u3.LoadFile(chris_filename)
	if reflect.DeepEqual(alice_data, chris_data) {
		t.Error("Revoked user got the file update")
		return
	}

}

func TestSameFilename(t *testing.T) {
	clear()
	// Create Alice and Bob
	u, _ := InitUser("alice", "fubar")
	u2, _ := InitUser("bob", "fubar")

	// Both create File f w/ same content
	data := []byte("content")
	u.StoreFile("f", data)
	u2.StoreFile("f", data)

	// Alice appends to File
	newdata := []byte("new content")
	_ = u.AppendFile("f", newdata)

	// Ensure that Bob's file wasn't affected
	dataload, err := u2.LoadFile("f")
	if !reflect.DeepEqual(dataload, data) || err != nil {
		t.Error("Couldn't handle same filename", err)
	}

	// Alice stores new file
	newdata = []byte("brand new content")
	u.StoreFile("f", newdata)

	// Ensure that Bob's file wasn't affected
	dataload, err = u2.LoadFile("f")
	if !reflect.DeepEqual(dataload, data) || err != nil {
		t.Error("Couldn't handle same filename", err)
	}
}