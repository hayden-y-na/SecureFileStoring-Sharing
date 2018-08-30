package proj2

import "testing"
// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInit(t *testing.T){
	t.Log("Initialization test")
	DebugPrint = true
	someUsefulThings()

	DebugPrint = false
	u, err := InitUser("alice","fubar")
	if err != nil {
		// t.Error says the test fails 
		t.Error("Failed to initialize user. ", err)
	}
	
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// You probably want many more tests here.
}


func TestStorage(t *testing.T){
	// And some more tests, because
	v, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user.", err)
		return
	}
	t.Log("Loaded user", v)
}

func TestStorage2(t *testing.T){
	// And some more tests, because
	v, err := GetUser("alic", "efubar")
	if err != nil {
		t.Log("Failed to reload user./ this is an intended error")
		return
	}
	t.Error("Loaded user", v)
}

func TestAttackGetUser(t *testing.T) {
	//check in case when anyone tries to attack
	v, err := GetUser("alice","imoutis")
	if err != nil {
		t.Log("no stop outis/ this is an intended error")
		return 
	}
	t.Error("This is not right.", v)
}


func TestNoUser(t *testing.T) {
	//check in case when anyone tries to attack
	v, err := GetUser("bob","imoutis")
	if err != nil {
		t.Log("no user found/ this is an intended error")
		return 
	}
	t.Error("This is not right.", v)
}



func TestStoreLoadFile(t *testing.T) {
	f, err1 := InitUser("alice","fubar")
	if (err1 != nil) {
		t.Log("something is wrong/ this is an intended error")
	}
	f.StoreFile("david", []byte("outis"))	
	data, err := f.LoadFile("outis")
	if err != nil {
		t.Log("not again/ this is an intended error")
	}
	data, err = f.LoadFile("david")
	if err != nil || string(data) != "outis" {
		t.Log("fetch screwed/ this is an intended error")
	}
	_, err = f.LoadFile("outis")
	if err != nil{
		t.Log("There is nothing idioto/ this is an intended error")
	}
	data, err = f.LoadFile("david")
	t.Error("LoadedData", data)
}

func TestAppendFile(t *testing.T) {
	u, err1 := InitUser("alice","fubar")
	u.StoreFile("david", []byte("outis"))	

	if (err1 != nil) {
		t.Error("something is wrong")//not happening
	}

	u.AppendFile("david", []byte("outiswannabe"))
	a := []byte("outis")
	b := []byte("outiswannabe")
	ab := append(a, b...)
	hoData, hoErr := u.LoadFile(string(ab))
	if hoErr != nil {
		t.Error("not again")
	}

	data, err := u.LoadFile("david")


	if err != nil || string(data) != string(ab) {
		
		t.Error("fetch screwed")
	}
	_, hoErr = u.LoadFile("outis")
	if hoErr != nil {
		t.Error("There is nothing idioto")
	} 
	t.Log("LoadedData", hoData)
}
//

// func TestShareAndReceiveFile(t *testing.T) {
// 	u, err := InitUser("alice","fubar")
// 	if (err != nil) {
// 		t.Error("something is wrong")
// 	}

// 	bo, err1 := InitUser("bob","boba")
// 	if err1 != nil {
// 		// t.Error says the test fails 
// 		t.Error("Failed to initialize user. ", err1)
// 	}
// 	u.StoreFile("hellobob", []byte("getmyonedollar!"))
	// m1 = u.ShareFile("hellobob", "bob", msgid) // not sure what MSGID has to be
	// bo.ReceiveFile("hellobob", "alice", msgid)
// }

// func TestShareWithOthers(t *testing.T) {
// 	//Initializing users
// 	q, err := InitUser("qeen","meme")
// 	w, err := InitUser("western","eastern")
// 	r, err := InitUser("ryan","gosling")
// 	t, err := InitUser("tsion","googler")

// 	//Sharing the file 
// 	m2 = u.ShareFile("hellobob", "queen", msgid) // not sure what MSGID has to be
// 	m3 = u.ShareFile("hellobob", "western", msgid) // not sure what MSGID has to be
// 	m4 = u.ShareFile("hellobob", "ryan", msgid) // not sure what MSGID has to be
// 	m5 = u.ShareFile("hellobob", "tsion", msgid) // not sure what MSGID has to be
	
// 	//Receiving the file
// 	q.ReceiveFile("hellobob", "alice", msgid) // still not sure MSGID
// 	w.ReceiveFile("hellobob", "alice", msgid)
// 	r.ReceiveFile("hellobob", "alice", msgid)
// 	t.ReceiveFile("hellobob", "alice", msgid)

// }

// func TestRevokeFile(t *testing.T) {
// 	}
//}

// // Removes access for all others.  
// func (userdata *User) RevokeFile(filename string) (err error){
// 	return 
// }
