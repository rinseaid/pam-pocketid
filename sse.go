package main

import (
	"fmt"
	"net/http"
	"time"
)

// sseAdminKey is the SSE channel key for admin subscribers. It uses a NUL byte
// prefix which cannot appear in valid usernames (^[a-zA-Z0-9._-]), preventing
// collision between a username "__admin__" and the admin broadcast channel.
const sseAdminKey = "\x00admin"

// registerSSE creates a new SSE channel for the given username and returns it.
func (s *Server) registerSSE(username string) chan string {
	ch := make(chan string, 16)
	s.sseMu.Lock()
	s.sseClients[username] = append(s.sseClients[username], ch)
	s.sseMu.Unlock()
	return ch
}

// unregisterSSE removes the given channel from the SSE client list for username.
func (s *Server) unregisterSSE(username string, ch chan string) {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	clients := s.sseClients[username]
	for i, c := range clients {
		if c == ch {
			s.sseClients[username] = append(clients[:i], clients[i+1:]...)
			break
		}
	}
	if len(s.sseClients[username]) == 0 {
		delete(s.sseClients, username)
	}
}

// broadcastSSE sends an event string to all SSE channels registered for username,
// and also to the sseAdminKey channel so admins see all events.
func (s *Server) broadcastSSE(username, event string) {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	for _, ch := range s.sseClients[username] {
		select {
		case ch <- event:
		default: // drop if channel full
		}
	}
	// Also broadcast to admin subscribers
	for _, ch := range s.sseClients[sseAdminKey] {
		select {
		case ch <- event:
		default:
		}
	}
}

// handleSSEEvents streams server-sent events for live dashboard updates.
// GET /api/events
func (s *Server) handleSSEEvents(w http.ResponseWriter, r *http.Request) {
	username := s.getSessionUser(r)
	if username == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering

	// Admin users subscribe to the sseAdminKey channel to see all users' events.
	sseKey := username
	if s.getSessionRole(r) == "admin" {
		sseKey = sseAdminKey
	}
	ch := s.registerSSE(sseKey)
	defer s.unregisterSSE(sseKey, ch)

	// Send initial keepalive
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	ctx := r.Context()
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case event := <-ch:
			fmt.Fprintf(w, "event: update\ndata: %s\n\n", event)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}
