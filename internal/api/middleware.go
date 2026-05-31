package api

import (
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
)

// RecoveryMiddleware recovers from panics and returns a 500 response.
func RecoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic recovered: %v", err)
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "internal server error",
				})
			}
		}()
		c.Next()
	}
}
