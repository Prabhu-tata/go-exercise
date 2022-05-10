package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var err error
var DB *gorm.DB

type User struct {
	gorm.Model
	Password string `gorm:"unique"`
	Mobile   int
	Email    string `gorm:"unique"`
	Isactive bool
}

type Authentication struct {
	Email    string `json:"Email"`
	Password string `json:"password"`
}

type Token struct {
	Email       string `json:"Email"`
	TokenString string `json:"token"`
}
type ChangePassword struct {
	Email            string `json: "Email"`
	Password         string `json: "Password"`
	Confirm_Password string `json: "Confirm_Password"`
}

func main() {
	database_connection()
	// defer Closedatabase(connection)
	router_path()
}

func database_connection() {
	dsn := "host=localhost user=postgres password=admin dbname=go_lang port=5432 sslmode=disable"
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	fmt.Println("Connection established successfully")
	DB.AutoMigrate(&User{})

}

// func Closedatabase(connection *gorm.DB) {
// 	sqldb := connection.DB()
// 	sqldb.Close()
// }

func get_users(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var user []User
	DB.Find(&user)
	json.NewEncoder(w).Encode(user)

}

func checkIfUserExists(user_id string) bool {
	var user User
	DB.First(&user, user_id)
	if user.ID == 0 {
		return false
	}
	return true
}

func get_userbyID(w http.ResponseWriter, r *http.Request) {
	user_id := mux.Vars(r)["id"]
	if checkIfUserExists(user_id) == false {
		json.NewEncoder(w).Encode("user Not Found!")
		return
	}
	var user User
	DB.First(&user, user_id)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)

}

func signup(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	var user User
	fmt.Println(r.Body)
	json.NewDecoder(r.Body).Decode(&user)
	fmt.Println(user.Password)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(user.Password), 8)
	user.Password = string(hashedPassword)
	fmt.Println(user.Password)
	DB.Create(&user)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func signin(w http.ResponseWriter, r *http.Request) {
	var authdetails Authentication
	err = json.NewDecoder(r.Body).Decode(&authdetails)
	if err != nil {
		log.Printf(" Error in reading body, %v", err)
		w.WriteHeader(500) // Return 500 Internal Server Error.
		return
	}

	var authuser User
	DB.Where("email = ?", authdetails.Email).First(&authuser)
	if authuser.Email == "" {
		w.Header().Set("Content-Type", "application/json")

		json.NewEncoder(w).Encode(err)
		return
	}
	fmt.Println(authdetails.Password, "PPPPP", authuser.Password)
	check := CheckPasswordHash(authdetails.Password, authuser.Password)

	if !check {
		var err error
		// err = SetError(err, "Username or Password is incorrect")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(err)
		return
	}

	validToken, err := GenerateJWT(authuser.Email, authuser.Password)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(err)
		return
	}

	var token Token
	token.Email = authuser.Email

	token.TokenString = validToken
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(token)
}

func change_password(w http.ResponseWriter, r *http.Request) {
	var changepassword ChangePassword
	user_id := mux.Vars(r)["id"]
	err = json.NewDecoder(r.Body).Decode(&changepassword)

	var authuser User
	DB.Where("email = ?", changepassword.Email).First(&authuser)
	fmt.Println(authuser.Email)
	if authuser.Email == "" {
		w.Header().Set("Content-Type", "application/json")
		// fmt.Println()
		w.WriteHeader(404)
		message := map[string]string{
			"Message": "This email is not available",
		}
		json.NewEncoder(w).Encode(message)
		return
	}
	// json.NewDecoder(r.Body).Decode(&changepassword)
	fmt.Println(changepassword.Password)
	if changepassword.Password != changepassword.Confirm_Password {
		w.Header().Set("Content-Type", "application/json")
		// fmt.Println()
		w.WriteHeader(404)
		message := map[string]string{
			"Message": "Password is mismatch",
		}
		json.NewEncoder(w).Encode(message)
		return
	}
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(changepassword.Password), 8)
	DB.Model(&User{}).Where("ID = ?", user_id).Update("Password", string(hashedPassword))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(authuser)
}

func Validate_token(w http.ResponseWriter, r *http.Request) {
	myToken := r.Header.Get("token")
	token, _ := jwt.Parse(myToken, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return token, nil
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(token)

}
func router_path() {
	r := mux.NewRouter()

	r.HandleFunc("/signup", signup).Methods("POST")
	r.HandleFunc("/signin", signin).Methods("POST")
	r.HandleFunc("/user", get_users).Methods("GET")
	r.HandleFunc("/user/{id}", get_userbyID).Methods("GET")
	r.HandleFunc("/reset/{id}", change_password).Methods("PUT")
	r.HandleFunc("/tokenvalidation", Validate_token).Methods("GET")
	log.Fatal(http.ListenAndServe(":7005", r))
}

func GenerateJWT(mail, password string) (string, error) {
	var secretkey string
	var mySigningKey = []byte(secretkey)
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["mail"] = mail
	claims["password"] = password
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString(mySigningKey)
	fmt.Println(tokenString)
	if err != nil {
		fmt.Errorf("Something Went Wrong: %s", err.Error())
		return "", err
	}
	return tokenString, nil
}
