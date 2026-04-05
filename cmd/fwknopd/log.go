package main

import (
	"fmt"
	"log"
	"log/syslog"
	"os"
	"path/filepath"
)

// spaLogger writes to a log file and optionally to syslog.
type spaLogger struct {
	fileLogger   *log.Logger
	syslogLogger *log.Logger
	verbose      bool
	logFile      *os.File
}

// newSPALogger creates a logger that writes to the specified log file
// and optionally to syslog.
func newSPALogger(logFilePath string, syslogIdent string, syslogFacility string, verbose bool, foreground bool) (*spaLogger, error) {
	sl := &spaLogger{verbose: verbose}

	// Set up file logging.
	if logFilePath != "" && !foreground {
		dir := filepath.Dir(logFilePath)
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("creating log directory %s: %w", dir, err)
		}

		f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			return nil, fmt.Errorf("opening log file %s: %w", logFilePath, err)
		}
		sl.logFile = f
		sl.fileLogger = log.New(f, "", log.LstdFlags)
	}

	// In foreground mode, log to stderr.
	if foreground {
		sl.fileLogger = log.New(os.Stderr, "", log.LstdFlags)
	}

	// Set up syslog.
	if syslogIdent != "" && !foreground {
		facility := parseSyslogFacility(syslogFacility)
		w, err := syslog.New(facility|syslog.LOG_INFO, syslogIdent)
		if err != nil {
			// Syslog failure is non-fatal — just warn.
			if sl.fileLogger != nil {
				sl.fileLogger.Printf("WARNING: syslog setup failed: %v", err)
			}
		} else {
			sl.syslogLogger = log.New(w, "", 0)
		}
	}

	return sl, nil
}

func (l *spaLogger) Close() {
	if l.logFile != nil {
		l.logFile.Close()
	}
}

func (l *spaLogger) Info(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if l.fileLogger != nil {
		l.fileLogger.Println("[INFO]", msg)
	}
	if l.syslogLogger != nil {
		l.syslogLogger.Println(msg)
	}
}

func (l *spaLogger) Warn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if l.fileLogger != nil {
		l.fileLogger.Println("[WARN]", msg)
	}
	if l.syslogLogger != nil {
		l.syslogLogger.Println("WARNING:", msg)
	}
}

func (l *spaLogger) Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if l.fileLogger != nil {
		l.fileLogger.Println("[ERROR]", msg)
	}
	if l.syslogLogger != nil {
		l.syslogLogger.Println("ERROR:", msg)
	}
}

func (l *spaLogger) Debug(format string, args ...interface{}) {
	if !l.verbose {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if l.fileLogger != nil {
		l.fileLogger.Println("[DEBUG]", msg)
	}
}

func parseSyslogFacility(s string) syslog.Priority {
	switch s {
	case "auth":
		return syslog.LOG_AUTH
	case "local0":
		return syslog.LOG_LOCAL0
	case "local1":
		return syslog.LOG_LOCAL1
	case "local2":
		return syslog.LOG_LOCAL2
	case "local3":
		return syslog.LOG_LOCAL3
	case "local4":
		return syslog.LOG_LOCAL4
	case "local5":
		return syslog.LOG_LOCAL5
	case "local6":
		return syslog.LOG_LOCAL6
	case "local7":
		return syslog.LOG_LOCAL7
	default:
		return syslog.LOG_DAEMON
	}
}
