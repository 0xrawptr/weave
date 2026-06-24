package api

import (
	"fmt"
	"time"
)

func generateWorkflowID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}
