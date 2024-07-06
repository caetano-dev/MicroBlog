package main

import (
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"golang.org/x/crypto/bcrypt"
)

type Post struct {
	Author    string
	Content   string
	Timestamp string
}

type User struct {
	ID       int
	Username string
	Password string // Note: This should be hashed before storage
}

// Function to generate mock data
func GenerateMockPosts() []Post {
	return []Post{
		{
			Author:    "Jane Jane",
			Content:   "I like eating rocks.",
			Timestamp: time.Now().Add(-48 * time.Hour).Format("Jan 02, 2006"),
		},
		{
			Author:    "John Smith",
			Content:   "This is another interesting post.",
			Timestamp: time.Now().Add(-24 * time.Hour).Format("Jan 02, 2006"),
		},
		{
			Author:    "Alice and Bob",
			Content:   "Here's some more insightful content.",
			Timestamp: time.Now().Format("Jan 02, 2006"),
		},
	}
}

func GenerateMockUsers() []User {
	password := "test"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	return []User{
		{
			ID:       1,
			Username: "test",
			Password: string(hashedPassword),
		},
	}
}

var templates = template.Must(template.ParseGlob("templates/*.tmpl"))

// Assuming you have a global variable for mock posts
var mockPosts = GenerateMockPosts()
var mockUsers = GenerateMockUsers()

func addPostHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == "POST" {
        r.ParseForm()
        content := r.FormValue("content")

        // Retrieve session cookie
        sessionCookie, err := r.Cookie("session")
        var username string
        if err != nil {
            // If there's an error (e.g., cookie not found), default to "Anonymous"
            username = "Anonymous"
        } else {
            // Extract username from session cookie
            username = sessionCookie.Value
        }

        // Create a new Post with the username as the author
        newPost := Post{
            Author:    username, // Use the username from the session cookie
            Content:   content,
            Timestamp: time.Now().Format("Jan 02, 2006"),
        }
        mockPosts = append([]Post{newPost}, mockPosts...)
        http.Redirect(w, r, "/", http.StatusFound)
    }
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")
		// Hash password
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		// Store the user
		storeUser(username, string(hashedPassword))
		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		// Render registration form
		fmt.Println("Registration page")
	}
}

func storeUser(username, password string) {
	// Add user to the mock User storage
	mockUsers = append(mockUsers, User{
		ID:       len(mockUsers) + 1,
		Username: username,
		Password: password,
	})
}

func getUserByUsername(username string) (User, error) {
	//get mock user by username
	for _, user := range mockUsers {
		if user.Username == username {
			return user, nil
		}
	}
	return User{}, fmt.Errorf("User not found")
}

func setSession(user User, w http.ResponseWriter) {
	// Set session cookie
	fmt.Println("Setting session cookie")
	http.SetCookie(w, &http.Cookie{
		Name:    "session",
		Value:   user.Username,
		Expires: time.Now().Add(24 * time.Hour),
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")
		// Retrieve user from storage and compare password
		fmt.Println("Login request")
		user, err := getUserByUsername(username)
		if err != nil {
			// Handle user not found
			fmt.Println("User not found")
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err == nil {
			// Passwords match
			// Set user session
			// Example: setSession(user, w)
			fmt.Println("Setting session cookie")
			setSession(user, w)
			http.Redirect(w, r, "/", http.StatusFound)
		} else {
			fmt.Println("Passwords do not match")
			http.Redirect(w, r, "/?error=invalid_credentials", http.StatusFound)
			// show massage in html saying that passwords do no match
		}
	} else {
		fmt.Println("Login page")
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	err := templates.ExecuteTemplate(w, "index", map[string]interface{}{
		"title": "Main website",
		"Posts": mockPosts,
		"error": r.URL.Query().Get("error"),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if user is logged in
		// Example: if !userIsLoggedIn(r) {
		fmt.Println("Checking if user is logged in")
		if false { // Placeholder condition
			http.Redirect(w, r, "/", http.StatusFound)
		} else {
			next.ServeHTTP(w, r)
		}
	})
}

func notFoundHandler(w http.ResponseWriter) {
	err := templates.ExecuteTemplate(w, "notfound", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func main() {
	router := chi.NewRouter()

	// Middleware
	router.Use(middleware.Logger)
	router.Use(authMiddleware) // Apply auth middleware globally or to specific routes

	// Routes
	router.Get("/", homeHandler)
	router.Post("/add-post", addPostHandler)
	router.Get("/login", loginHandler)
	router.Post("/login", loginHandler)
	router.Get("/register", registerHandler)
	router.Post("/register", registerHandler)
	router.NotFound(func(w http.ResponseWriter, r *http.Request) {
		notFoundHandler(w)
	})

	http.ListenAndServe(":8080", router)
}

