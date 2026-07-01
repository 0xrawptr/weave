package middleware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type AuthConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	APIKey  string `yaml:"api_key" json:"api_key"`
	Admin   struct {
		Username string `yaml:"username" json:"username"`
		Password string `yaml:"password" json:"password"`
	} `yaml:"admin"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type TokenStore interface {
	ValidateToken(ctx context.Context, token string) (string, error)
	CreateToken(ctx context.Context, username string) (string, error)
	VerifyPassword(ctx context.Context, username, password string) (bool, error)
}

type simpleTokenStore struct {
	tokens map[string]tokenEntry // token -> username
	users  map[string]string     // username -> password_hash (sha256)
}

type tokenEntry struct {
	username  string
	createdAt time.Time
}

func newSimpleTokenStore() *simpleTokenStore {
	return &simpleTokenStore{
		tokens: make(map[string]tokenEntry),
		users:  make(map[string]string),
	}
}

func (s *simpleTokenStore) setUser(username, passwordHash string) {
	s.users[username] = passwordHash
}

func (s *simpleTokenStore) VerifyPassword(_ context.Context, username, password string) (bool, error) {
	stored, ok := s.users[username]
	if !ok {
		return false, nil
	}
	hash := sha256Hash(password)
	return subtle.ConstantTimeCompare([]byte(hash), []byte(stored)) == 1, nil
}

func (s *simpleTokenStore) CreateToken(_ context.Context, username string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	s.tokens[token] = tokenEntry{username: username, createdAt: time.Now()}
	return token, nil
}

func (s *simpleTokenStore) ValidateToken(_ context.Context, token string) (string, error) {
	entry, ok := s.tokens[token]
	if !ok {
		return "", nil
	}
	return entry.username, nil
}

func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// AuthMiddleware returns a Gin middleware that enforces authentication
// unless auth is disabled or the route is in the skip list.
func AuthMiddleware(cfg AuthConfig, store TokenStore) gin.HandlerFunc {
	if !cfg.Enabled {
		return func(c *gin.Context) { c.Next() }
	}

	return func(c *gin.Context) {
		// Check API key first
		if cfg.APIKey != "" {
			if subtle.ConstantTimeCompare([]byte(c.GetHeader("X-API-Key")), []byte(cfg.APIKey)) == 1 {
				c.Set("auth_method", "api_key")
				c.Next()
				return
			}
			authHeader := c.GetHeader("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				if subtle.ConstantTimeCompare([]byte(authHeader[7:]), []byte(cfg.APIKey)) == 1 {
					c.Set("auth_method", "api_key")
					c.Next()
					return
				}
			}
		}

		// Check token
		token := c.GetHeader("X-Auth-Token")
		if token == "" {
			// Also check Authorization: Bearer <token>
			authHeader := c.GetHeader("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = authHeader[7:]
			}
		}
		if token == "" {
			token = c.Query("token")
		}

		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required", "code": 401})
			return
		}

		username, err := store.ValidateToken(c.Request.Context(), token)
		if err != nil || username == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token", "code": 401})
			return
		}

		c.Set("auth_method", "token")
		c.Set("username", username)
		c.Next()
	}
}

// LoginHandler handles POST /api/v1/auth/login
func LoginHandler(cfg AuthConfig, store TokenStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !cfg.Enabled {
			c.JSON(http.StatusOK, gin.H{"message": "authentication is disabled", "token": ""})
			return
		}

		var req LoginRequest
		if err := json.NewDecoder(c.Request.Body).Decode(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		if req.Username == "" || req.Password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username and password are required"})
			return
		}

		ok, err := store.VerifyPassword(c.Request.Context(), req.Username, req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "authentication error"})
			return
		}
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}

		token, err := store.CreateToken(c.Request.Context(), req.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"token":    token,
			"username": req.Username,
			"message":  "login successful",
		})
	}
}

// NewAuthStore creates a simple in-memory token store with default admin credentials.
func NewAuthStore(cfg AuthConfig) TokenStore {
	store := newSimpleTokenStore()

	if cfg.Admin.Username != "" && cfg.Admin.Password != "" {
		store.setUser(cfg.Admin.Username, sha256Hash(cfg.Admin.Password))
		log.Printf("auth: admin user configured (username=%s)", cfg.Admin.Username)
	} else {
		// Default admin:admin
		store.setUser("admin", sha256Hash("admin"))
		log.Println("auth: using default admin/admin credentials")
	}

	return store
}
