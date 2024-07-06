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
	ID        int
	UserID    int
	Author    string
	Content   string
	Timestamp string
}

type User struct {
	ID       int
	Username string
	Password string
}

type PostWithAuthor struct {
	Post
	Username string
}

// Function to generate mock data
func GenerateMockPosts() []Post {
	return []Post{
		{
			ID:        1,
			UserID:    1,
			Content:   "I like eating rocks.",
			Timestamp: time.Now().Add(-48 * time.Hour).Format("Jan 02, 2006"),
		},
		{
			ID:        2,
			UserID:    2,
			Content:   "This is another interesting post.",
			Timestamp: time.Now().Add(-24 * time.Hour).Format("Jan 02, 2006"),
		},
		{
			ID:        3,
			UserID:    1,
			Content:   "Here's some more insightful content.",
			Timestamp: time.Now().Format("Jan 02, 2006"),
		},
	}
}

func GenerateMockUsers() []User {
	password := "1234"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	return []User{
		{
			ID:       1,
			Username: "user1",
			Password: string(hashedPassword),
		},
		{
			ID:       2,
			Username: "user2",
			Password: string(hashedPassword),
		},
	}
}

func GenerateMockPostsWithAuthors() []PostWithAuthor {
	var postsWithAuthors []PostWithAuthor
	for _, post := range mockPosts {
		user, err := getUserByID(post.UserID)
		if err != nil {
			continue
		}
		postsWithAuthors = append(postsWithAuthors, PostWithAuthor{
			Post:     post,         
			Username: user.Username,
		})
	}
	return postsWithAuthors
}

var templates = template.Must(template.ParseGlob("templates/*.tmpl"))

// Assuming you have a global variable for mock posts
var mockPosts = GenerateMockPosts()
var mockUsers = GenerateMockUsers()
var mockPostsWithAuthors = GenerateMockPostsWithAuthors()

func addPostHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Print("Add post handler")
	if r.Method == "POST" {
		r.ParseForm()
		content := r.FormValue("content")

		// Retrieve session cookie
		currentUsernameCookie, err := r.Cookie("username")
		if err != nil {
			http.Redirect(w, r, "/?error=invalid_credentials", http.StatusFound)
			return
		}
		// set currentUsernameCookie as username
		currentUsername := currentUsernameCookie.Value

		currentUser, err := getUserByUsername(currentUsername)
		if err != nil {
			http.Redirect(w, r, "/?error=invalid_credentials", http.StatusFound)
			return
		}

		userID := currentUser.ID

		// Create a new Post with the username as the author
		newPost := Post{
			ID:        len(mockPosts) + 1,
			UserID:    userID,
			Author:    currentUsername,
			Content:   content,
			Timestamp: time.Now().Format("Jan 02, 2006"),
		}
		mockPosts = append([]Post{newPost}, mockPosts...)

		mockPostsWithAuthors = GenerateMockPostsWithAuthors()

		fmt.Println("New post added")
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		storeUser(username, string(hashedPassword))
		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		// Render registration form
		fmt.Println("Registration page")
	}
}

func storeUser(username, password string) {
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
		Name:    "username",
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
		"Posts": mockPostsWithAuthors,
		"error": r.URL.Query().Get("error"),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func getUserByID(userID int) (User, error) {
	//get mock user by userID
	for _, user := range mockUsers {
		if user.ID == userID {
			return user, nil
		}
	}
	return User{}, fmt.Errorf("User not found")
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if user is logged in
		// Example: if !userIsLoggedIn(r) {
		fmt.Println("Checking if user is logged in")
		if false { // Placeholder condition
			// TODO: ask user to login
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
