package logging

import (
	"encoding/csv"
	"fmt"
	"os"
	"time"
)

// LogEntry represents a log entry structure
type LogEntry struct {
	Timestamp string
	Level     string
	Message   string
}

// writeLogsToCSV writes a slice of LogEntry to a CSV file
func writeLogsToCSV(filePath string, entries []LogEntry) error {
	// Open the CSV file in append mode
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	// Create a CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write log entries to the CSV file
	for _, entry := range entries {
		record := []string{entry.Timestamp, entry.Level, entry.Message}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("error writing record to CSV: %v", err)
		}
	}

	return nil
}

// log writes a log entry to the CSV file
func Log(level, message string) {
	filePath := "logs.csv"
	entry := LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Level:     level,
		Message:   message,
	}
	if err := writeLogsToCSV(filePath, []LogEntry{entry}); err != nil {
		fmt.Printf("Failed to write log: %v\n", err)
	}
}
