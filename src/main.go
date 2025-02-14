package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

// Secret Key for JWT (In a real system, store this securely!)
var jwtSecret = []byte("supersecretkey")

// Database connection
var db *sql.DB

// Logger
var logger *zap.Logger

// User struct
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"` // e.g., "admin" or "user"
}

// Transaction struct
type Transaction struct {
	ID        int     `json:"id"`
	UserID    int     `json:"user_id"`
	Amount    float64 `json:"amount"`
	Timestamp string  `json:"timestamp"`
}

// JWT Claims
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

// Initialize logger
func init() {
	logger, _ = zap.NewProduction()
	defer logger.Sync()
}

// Database connection setup
func initDB() {
	var err error
	db, err = sql.Open("postgres", "host=your-rds-endpoint user=youruser password=yourpassword dbname=yourdb sslmode=disable")
	if err != nil {
		logger.Fatal("Failed to connect to database", zap.Error(err))
	}
}

// Health check handler
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("Health check endpoint hit")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Service is healthy")
}

// User login handler (Generates JWT Token)
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Check user in database
	var storedPassword, role string
	err = db.QueryRow("SELECT password, role FROM users WHERE username=$1", user.Username).Scan(&storedPassword, &role)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// For simplicity, no hashing is implemented here (In production, use bcrypt)
	if user.Password != storedPassword {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate JWT Token
	expirationTime := time.Now().Add(1 * time.Hour)
	claims := &Claims{
		Username: user.Username,
		Role:     role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

// Middleware to validate JWT Token
func jwtMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Store user role in request context
		ctx := context.WithValue(r.Context(), "role", claims.Role)
		next(w, r.WithContext(ctx))
	}
}

// Get all transactions (Admin only)
func getAllTransactionsHandler(w http.ResponseWriter, r *http.Request) {
	role := r.Context().Value("role").(string)
	if role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	rows, err := db.Query("SELECT id, user_id, amount, timestamp FROM transactions")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var transactions []Transaction
	for rows.Next() {
		var transaction Transaction
		if err := rows.Scan(&transaction.ID, &transaction.UserID, &transaction.Amount, &transaction.Timestamp); err != nil {
			http.Error(w, "Error scanning results", http.StatusInternalServerError)
			return
		}
		transactions = append(transactions, transaction)
	}

	json.NewEncoder(w).Encode(transactions)
}

// Create a new transaction (Authenticated user)
func createTransactionHandler(w http.ResponseWriter, r *http.Request) {
	var transaction Transaction
	err := json.NewDecoder(r.Body).Decode(&transaction)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("INSERT INTO transactions (user_id, amount, timestamp) VALUES ($1, $2, $3)",
		transaction.UserID, transaction.Amount, time.Now().Format(time.RFC3339))
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Transaction successful"})
}

// Protected route example
func adminHandler(w http.ResponseWriter, r *http.Request) {
	role := r.Context().Value("role").(string)
	if role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Welcome, Admin!")
}

func main() {
	// Initialize DB connection
	initDB()
	defer db.Close()

	router := mux.NewRouter()

	// Public routes
	router.HandleFunc("/health", healthCheckHandler).Methods("GET")
	router.HandleFunc("/login", loginHandler).Methods("POST")

	// Protected routes
	router.HandleFunc("/transactions", jwtMiddleware(getAllTransactionsHandler)).Methods("GET") // Admin only
	router.HandleFunc("/transaction", jwtMiddleware(createTransactionHandler)).Methods("POST")  // Users
	router.HandleFunc("/admin", jwtMiddleware(adminHandler)).Methods("GET")                     // Admin only

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	logger.Info("Starting secure API...", zap.String("port", port))
	log.Fatal(http.ListenAndServe(":"+port, router))
}
