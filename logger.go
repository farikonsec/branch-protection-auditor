package main

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
)

// Logger provides a minimal thread-safe structured logger.
type Logger struct {
	mu sync.Mutex
}

func (l *Logger) Info(message string, fields map[string]interface{}) {
	l.log("INFO", message, fields)
}

func (l *Logger) Error(message string, fields map[string]interface{}) {
	l.log("ERROR", message, fields)
}

func (l *Logger) log(level, message string, fields map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	logEntry := map[string]interface{}{
		"level":   level,
		"message": message,
	}
	for k, v := range fields {
		logEntry[k] = v
	}
	b, err := jsonMarshal(logEntry)
	if err != nil {
		log.Printf("Failed to marshal log entry: %v", err)
		return
	}
	fmt.Println(string(b))
}

func jsonMarshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
