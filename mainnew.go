package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"exmaples.com/myapp/logging"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

var jwtKey = []byte("your-secret-key")

// Configuration struct represents a configuration item loaded from CSV
type Configuration struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// UserCache stores logged-in users with timestamps
var userCache = make(map[string]time.Time)
var mu sync.Mutex // Mutex for thread-safe map access

func main() {
	var dir string
	flag.StringVar(&dir, "dir", ".", "the directory to serve files from. Defaults to the current dir")
	flag.Parse()

	// Log the directory being served
	logging.Log("INFO", fmt.Sprintf("Serving static files from directory: %s", dir))

	// Create a new router
	r := mux.NewRouter()

	// Static file serving
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(dir))))
	logging.Log("INFO", "Static file server set up at /static/")

	// Load configuration from CSV file
	config, err := loadConfig("Config.csv")
	if err != nil {
		logging.Log("ERROR", fmt.Sprintf("Error loading config: %v", err))
		log.Fatalf("Error loading config: %v", err)
	}
	logging.Log("INFO", "Configuration loaded successfully")

	// Example endpoint to get config
	r.HandleFunc("/config/{key}", func(w http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		key := params["key"]

		for _, item := range config {
			if item.Key == key {
				json.NewEncoder(w).Encode(item)
				return
			}
		}

		w.WriteHeader(http.StatusNotFound)
		logging.Log("WARN", fmt.Sprintf("Config key '%s' not found", key))
	}).Methods("GET")

	// Route to handle user login
	r.HandleFunc("/login", loginHandler).Methods("POST")

	// Route to handle restricted access
	r.HandleFunc("/restricted", authMiddleware(accessRestrictedHandler)).Methods("GET")

	// Create and configure the server
	srv := &http.Server{
		Handler:      r,
		Addr:         "127.0.0.1:8000",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	// Log the server startup
	logging.Log("INFO", "Starting server on port 8000")
	fmt.Println("Server running on port 8000")

	// Start the server
	if err := srv.ListenAndServe(); err != nil {
		logging.Log("ERROR", fmt.Sprintf("Server error: %v", err))
		log.Fatalf("Server error: %v", err)
	}

}

// Function to load configuration from CSV file
func loadConfig(filename string) ([]Configuration, error) {
	logging.Log("INFO", fmt.Sprintf("Loading config from '%s'", filename))
	log.Println(filename)
	var config []Configuration

	file, err := os.Open(filename)
	if err != nil {
		return config, fmt.Errorf("error opening config file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	for {
		line, err := reader.Read()
		if err == csv.ErrFieldCount {
			// Handle incomplete lines
			continue
		} else if err == io.EOF {
			break
		} else if err != nil {
			return config, fmt.Errorf("error reading config file: %v", err)
		}

		// Assuming CSV structure is Key,Value
		if len(line) >= 2 {
			item := Configuration{
				Key:   line[0],
				Value: line[1],
			}
			config = append(config, item)
		} else {
			log.Printf("Invalid line in CSV: %v", line)
		}
	}

	return config, nil
}

// Function to authenticate user (replace with your actual authentication logic)
func authenticate(username, password string) bool {
	// Example: hardcoded authentication
	return username == "admin" && password == "admin"
}

// Login handler generates a JWT for a user
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		logging.Log("ERROR", "Failed to decode login credentials")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !authenticate(creds.Username, creds.Password) {
		logging.Log("WARN", fmt.Sprintf("Failed login attempt for user: %s", creds.Username))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &jwt.StandardClaims{
		ExpiresAt: expirationTime.Unix(),
		Subject:   creds.Username,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		logging.Log("ERROR", "Failed to sign JWT token")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	mu.Lock()
	userCache[creds.Username] = time.Now()
	mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "jwt",
		Value:    tokenString,
		Expires:  expirationTime,
		HttpOnly: true,
	})
	logging.Log("INFO", fmt.Sprintf("User '%s' logged in successfully", creds.Username))

	w.WriteHeader(http.StatusOK)
}

// Middleware function to check JWT token and authorize user
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("jwt")
		if err != nil {
			if err == http.ErrNoCookie {
				w.WriteHeader(http.StatusUnauthorized)
				logging.Log("WARN", "No JWT cookie found")
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			logging.Log("ERROR", "Failed to read JWT cookie")
			return
		}

		tokenString := cookie.Value
		claims := &jwt.StandardClaims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				w.WriteHeader(http.StatusUnauthorized)
				logging.Log("WARN", "Invalid JWT signature")
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			logging.Log("ERROR", "Failed to parse JWT token")
			return
		}

		if !token.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			logging.Log("WARN", "JWT token is not valid")
			return
		}

		// Check if user is authenticated
		mu.Lock()
		_, ok := userCache[claims.Subject]
		mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			logging.Log("WARN", fmt.Sprintf("User '%s' not found in cache", claims.Subject))
			return
		}

		next.ServeHTTP(w, r)
	}
}

// Handler for accessing restricted endpoint
//func accessRestrictedHandler(w http.ResponseWriter, r *http.Request) {
//	logging.Log("INFO", "Restricted endpoint accessed")
//	w.Write([]byte("Access restricted\n"))
//}

func accessRestrictedHandler(w http.ResponseWriter, r *http.Request) {
	fileContent, err := ioutil.ReadFile("restricted_data.txt")
	if err != nil {
		logging.Log("ERROR", "Failed to read restricted data file: "+err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	currentTime := time.Now().Format("2006-01-02 15:04:05")
	responseContent := fmt.Sprintf("%s\n\nCurrent date and time: %s", string(fileContent), currentTime)

	logging.Log("INFO", "Restricted endpoint accessed")

	w.Write([]byte(responseContent))
	//w.Write(fileContent)
}

// Struct for credentials received from client
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
