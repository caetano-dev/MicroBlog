package main

import (
	"net/http"
	"time"
	"html/template"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Post struct {
	Author    string
	Content   string
	Timestamp string
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

var templates = template.Must(template.ParseGlob("templates/*.tmpl"))
// Assuming you have a global variable for mock posts
var mockPosts = GenerateMockPosts()

func addPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseForm()
		content := r.FormValue("content")
		// Create a new Post
		newPost := Post{
			Author:    "Anonymous", // Update this as needed
			Content:   content,
			Timestamp: time.Now().Format("Jan 02, 2006"),
		}
		// Append to mock posts (assuming mockPosts is your global variable)

		//add new post to the beginning of the slice
		mockPosts = append([]Post{newPost}, mockPosts...)
		// Redirect to home page to see the new post
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func main() {
    router := chi.NewRouter()

    // Middleware
    router.Use(middleware.Logger)
    router.Use(middleware.Recoverer)

    // Serve static files
    router.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
	// Register the add post handler
	router.Post("/add-post", addPostHandler)
    // Define a route
    router.Get("/", func(w http.ResponseWriter, r *http.Request) {
        //posts := GenerateMockPosts()
        err := templates.ExecuteTemplate(w, "index", map[string]interface{}{
            "title": "Main website",
            "Posts": mockPosts,
        })
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
        }
    })

    // Start the server
    http.ListenAndServe(":8080", router)
}