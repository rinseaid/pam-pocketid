package main

import (
	"fmt"
	"log"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}


// handleAdmin renders the admin overview page at /admin.
// GET /admin
func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// handleAdminInfo shows server configuration and system information.
// GET /admin/info
func (s *Server) handleAdminInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Handle language change via query param
	if setLanguageCookie(w, r) {
		return
	}
	lang := detectLanguage(r)
	t := T(lang)

	username := s.getSessionUser(r)
	if username == "" {
		setFlashCookie(w, "expired:")
		http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
		return
	}
	s.setSessionCookie(w, username, s.getSessionRole(r))

	if s.getSessionRole(r) != "admin" {
		http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
		return
	}

	// Server configuration values
	gracePeriod := formatDuration(s.cfg.GracePeriod)
	challengeTTL := formatDuration(s.cfg.ChallengeTTL)

	breakglassType := s.cfg.ClientBreakglassPasswordType
	if breakglassType == "" {
		breakglassType = t("not_configured")
	}

	breakglassRotation := t("not_configured")
	if s.cfg.ClientBreakglassRotationDays > 0 {
		breakglassRotation = fmt.Sprintf("%d %s", s.cfg.ClientBreakglassRotationDays, t("days"))
	}

	tokenCache := t("disabled")
	if s.cfg.ClientTokenCacheEnabled != nil && *s.cfg.ClientTokenCacheEnabled {
		tokenCache = t("enabled")
	}

	escrowConfigured := t("not_configured")
	if s.cfg.EscrowCommand != "" {
		escrowConfigured = t("configured")
	}

	notifyConfigured := t("not_configured")
	if s.cfg.NotifyCommand != "" {
		notifyConfigured = t("configured")
	}

	hostRegistryEnabled := s.hostRegistry.IsEnabled()
	hostRegistryStatus := t("host_registry_global_secret")
	if hostRegistryEnabled {
		hostRegistryStatus = fmt.Sprintf(t("enabled_n_hosts"), len(s.hostRegistry.RegisteredHosts()))
	}

	sessionPersistence := t("disabled")
	if s.cfg.SessionStateFile != "" {
		sessionPersistence = s.cfg.SessionStateFile
	}

	// System info
	uptime := time.Since(serverStartTime)
	uptimeStr := formatDuration(uptime)

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	allocMB := float64(memStats.Alloc) / 1024 / 1024
	sysMB := float64(memStats.Sys) / 1024 / 1024
	memUsage := fmt.Sprintf("%.1f MB alloc / %.1f MB sys", allocMB, sysMB)

	activeSessions := len(s.store.AllActiveSessions())

	// Read timezone from cookie for profile dropdown display
	adminTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, err := time.LoadLocation(c.Value); err == nil {
			adminTZ = c.Value
		}
	}

	w.Header().Set("Content-Type", "text/html")
	if err := adminTmpl.Execute(w, map[string]interface{}{
		"Username":            username,
		"Initial":             strings.ToUpper(username[:1]),
		"Avatar":              getAvatar(r),
		"Timezone":            adminTZ,
		"ActivePage":          "admin",
		"AdminTab":            "info",
		"Theme":               getTheme(r),
		"CSPNonce":            r.Context().Value("csp-nonce"),
		"T":                   T(lang),
		"Lang":                lang,
		"Languages":           supportedLanguages,
		"IsAdmin":             true,
		"Version":             version,
		"GracePeriod":         gracePeriod,
		"ChallengeTTL":        challengeTTL,
		"BreakglassType":      breakglassType,
		"BreakglassRotation":  breakglassRotation,
		"TokenCache":          tokenCache,
		"DefaultPageSize":     s.cfg.DefaultHistoryPageSize,
		"EscrowConfigured":    escrowConfigured,
		"NotifyConfigured":    notifyConfigured,
		"HostRegistry":        hostRegistryStatus,
		"SessionPersistence":  sessionPersistence,
		"OneTapMaxAge":        formatDuration(s.cfg.OneTapMaxAge),
		"AdminGroups":         func() string { if len(s.cfg.AdminGroups) == 0 { return t("not_configured") }; return strings.Join(s.cfg.AdminGroups, ", ") }(),
		"AdminApprovalHosts":  func() string { if len(s.cfg.AdminApprovalHosts) == 0 { return t("not_configured") }; return strings.Join(s.cfg.AdminApprovalHosts, ", ") }(),
		"Uptime":              uptimeStr,
		"GoVersion":           runtime.Version(),
		"OSArch":              runtime.GOOS + "/" + runtime.GOARCH,
		"Goroutines":          runtime.NumGoroutine(),
		"MemUsage":            memUsage,
		"ActiveSessionsCount": activeSessions,
	}); err != nil {
		log.Printf("ERROR: template execution: %v", err)
	}
}

// handleAdminUsers renders the admin users list at /admin/users.
// GET /admin/users
func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Handle language change via query param
	if setLanguageCookie(w, r) {
		return
	}
	lang := detectLanguage(r)
	t := T(lang)

	username := s.getSessionUser(r)
	if username == "" {
		setFlashCookie(w, "expired:")
		http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
		return
	}
	s.setSessionCookie(w, username, s.getSessionRole(r))

	if s.getSessionRole(r) != "admin" {
		http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
		return
	}

	// Parse flash messages
	var flashes []string
	if flashParam := getAndClearFlash(w, r); flashParam != "" {
		for _, f := range strings.Split(flashParam, ",") {
			parts := strings.SplitN(f, ":", 2)
			if len(parts) == 2 {
				switch parts[0] {
				case "removed_user":
					flashes = append(flashes, t("removed_user_on")+" "+parts[1])
				}
			}
		}
	}

	users := s.store.AllUsers()

	// Fetch group permissions from Pocket ID (cached)
	var userPerms map[string][]pocketIDGroupInfo
	if s.pocketIDClient != nil {
		perms, err := s.pocketIDClient.GetUserPermissions()
		if err != nil {
			log.Printf("WARNING: fetching Pocket ID permissions: %v", err)
		} else {
			userPerms = perms
		}
	}

	// Merge Pocket ID users that haven't yet used pam-pocketid
	if userPerms != nil {
		userSet := make(map[string]bool, len(users))
		for _, u := range users {
			userSet[u] = true
		}
		for uname := range userPerms {
			if !userSet[uname] {
				users = append(users, uname)
				userSet[uname] = true
			}
		}
		sort.Strings(users)
	}

	type userView struct {
		Username       string
		ActiveSessions int
		LastActive     string
		LastActiveAgo  string
		Groups         []pocketIDGroupInfo
		SudoCommands   []string
		SudoHosts      []string
		SudoAllCmds    bool
		SudoAllHosts   bool
	}

	now := time.Now()
	csrfTs := fmt.Sprintf("%d", now.Unix())
	csrfToken := computeCSRFToken(s.cfg.SharedSecret, username, csrfTs)

	var userViews []userView
	for _, u := range users {
		sessions := s.store.ActiveSessions(u)
		history := s.store.ActionHistory(u)
		lastActive := ""
		lastActiveAgo := ""
		if len(history) > 0 {
			// Find most recent entry
			var latest time.Time
			for _, e := range history {
				if e.Timestamp.After(latest) {
					latest = e.Timestamp
				}
			}
			lastActive = latest.Format("2006-01-02 15:04")
			lastActiveAgo = timeAgoI18n(latest, t)
		}
		uv := userView{
			Username:       u,
			ActiveSessions: len(sessions),
			LastActive:     lastActive,
			LastActiveAgo:  lastActiveAgo,
		}
		// Filter to only sudo-relevant groups (those with sudoCommands claim)
		var sudoGroups []pocketIDGroupInfo
		for _, g := range userPerms[u] {
			if g.SudoCommands != "" {
				sudoGroups = append(sudoGroups, g)
			}
		}
		uv.Groups = sudoGroups
		// Build deduplicated commands and hosts lists for click-to-expand UI
		seenCmds := make(map[string]bool)
		seenHosts := make(map[string]bool)
		for _, g := range uv.Groups {
			// Commands
			if g.SudoCommands == "ALL" {
				uv.SudoAllCmds = true
			} else if g.SudoCommands != "" {
				for _, c := range strings.Split(g.SudoCommands, ",") {
					if cmd := strings.TrimSpace(c); cmd != "" && !seenCmds[cmd] {
						uv.SudoCommands = append(uv.SudoCommands, cmd)
						seenCmds[cmd] = true
					}
				}
			}
			// Hosts
			if g.SudoHosts == "" || g.SudoHosts == "ALL" {
				uv.SudoAllHosts = true
			} else {
				for _, p := range strings.Split(g.SudoHosts, ",") {
					if h := strings.TrimSpace(p); h != "" && !seenHosts[h] {
						uv.SudoHosts = append(uv.SudoHosts, h)
						seenHosts[h] = true
					}
				}
			}
		}
		// Skip users with no sudo groups AND no pam-pocketid activity
		hasPamActivity := uv.ActiveSessions > 0 || uv.LastActive != ""
		if len(uv.Groups) == 0 && !hasPamActivity {
			continue
		}
		userViews = append(userViews, uv)
	}

	adminTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, err := time.LoadLocation(c.Value); err == nil {
			adminTZ = c.Value
		}
	}

	w.Header().Set("Content-Type", "text/html")
	if err := adminTmpl.Execute(w, map[string]interface{}{
		"Username":   username,
		"Initial":    strings.ToUpper(username[:1]),
		"Avatar":     getAvatar(r),
		"Timezone":   adminTZ,
		"Flashes":    flashes,
		"ActivePage": "admin",
		"AdminTab":   "users",
		"Theme":      getTheme(r),
		"CSPNonce":   r.Context().Value("csp-nonce"),
		"T":          T(lang),
		"Lang":       lang,
		"Languages":  supportedLanguages,
		"IsAdmin":    true,
		"Users":      userViews,
		"CSRFToken":  csrfToken,
		"CSRFTs":     csrfTs,
	}); err != nil {
		log.Printf("ERROR: template execution: %v", err)
	}
}

// handleAdminHosts renders the admin hosts page at /admin/hosts.
// GET /admin/hosts
func (s *Server) handleAdminHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Handle language change via query param
	if setLanguageCookie(w, r) {
		return
	}
	lang := detectLanguage(r)
	t := T(lang)

	username := s.getSessionUser(r)
	if username == "" {
		setFlashCookie(w, "expired:")
		http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
		return
	}
	s.setSessionCookie(w, username, s.getSessionRole(r))

	if s.getSessionRole(r) != "admin" {
		http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
		return
	}

	// Resolve timezone for flash time formatting
	flashTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, err2 := time.LoadLocation(c.Value); err2 == nil {
			flashTZ = c.Value
		}
	}
	flashLoc, _ := time.LoadLocation(flashTZ)
	formatFlashTime := func(unixStr string) string {
		unix, err := strconv.ParseInt(unixStr, 10, 64)
		if err != nil {
			return ""
		}
		return time.Unix(unix, 0).In(flashLoc).Format("Jan 2, 3:04 PM")
	}

	// Parse flash messages from cookie
	var flashes []string
	if flashParam := getAndClearFlash(w, r); flashParam != "" {
		for _, f := range strings.Split(flashParam, ",") {
			parts := strings.SplitN(f, ":", 5)
			if len(parts) < 2 {
				continue
			}
			switch parts[0] {
			case "elevated":
				if len(parts) == 4 {
					flashes = append(flashes, t("elevated_session_on")+" "+parts[1]+" ("+parts[2]+") "+t("until")+" "+formatFlashTime(parts[3]))
				} else {
					flashes = append(flashes, t("elevated_session_on")+" "+parts[1])
				}
			case "extended":
				if len(parts) == 4 {
					flashes = append(flashes, t("extended_session_on")+" "+parts[1]+" ("+parts[2]+") "+t("until")+" "+formatFlashTime(parts[3]))
				} else {
					flashes = append(flashes, t("extended_session_on")+" "+parts[1])
				}
			case "extended_all":
				flashes = append(flashes, fmt.Sprintf(t("extended_n_sessions"), atoi(parts[1])))
			case "revoked":
				if len(parts) == 3 {
					flashes = append(flashes, t("revoked_session_on")+" "+parts[1]+" ("+parts[2]+")")
				} else {
					flashes = append(flashes, t("revoked_session_on")+" "+parts[1])
				}
			case "revoked_all":
				flashes = append(flashes, fmt.Sprintf(t("revoked_n_sessions"), atoi(parts[1])))
			case "rotated":
				flashes = append(flashes, t("rotated_breakglass_on")+" "+parts[1])
			case "rotated_all":
				flashes = append(flashes, fmt.Sprintf(t("rotated_n_hosts"), atoi(parts[1])))
			}
		}
	}

	hosts := s.store.KnownHosts(username)
	escrowed := s.store.EscrowedHosts()

	// Merge escrowed hosts into the known hosts list
	escrowedSet := make(map[string]bool)
	for h := range escrowed {
		if s.hostRegistry.IsEnabled() && !s.hostRegistry.IsUserAuthorized(h, username) {
			continue
		}
		escrowedSet[h] = true
		found := false
		for _, kh := range hosts {
			if kh == h {
				found = true
				break
			}
		}
		if !found {
			hosts = append(hosts, h)
		}
	}
	sort.Strings(hosts)

	// Default rotation days for escrow validity
	rotationDays := 90
	if s.cfg.ClientBreakglassRotationDays > 0 {
		rotationDays = s.cfg.ClientBreakglassRotationDays
	}

	// Merge registered hosts into the known hosts list
	if s.hostRegistry.IsEnabled() {
		for _, rh := range s.hostRegistry.HostsForUser(username) {
			found := false
			for _, kh := range hosts {
				if kh == rh {
					found = true
					break
				}
			}
			if !found {
				hosts = append(hosts, rh)
			}
		}
		sort.Strings(hosts)
	}

	type hostUserView struct {
		Username  string
		Active    bool
		Remaining string
		Hostname  string
	}

	type hostView struct {
		Hostname      string
		HostUsers     []hostUserView
		Escrowed      bool
		EscrowAge     string
		EscrowExpired bool
		EscrowLink    string
		Group         string
	}

	// usersForHost returns sorted usernames with sudo access to hostname from Pocket ID claims.
	// Falls back to allUsers if userPerms is empty.
	usersForHost := func(hostname string, userPerms map[string][]pocketIDGroupInfo, allUsers []string) []string {
		if len(userPerms) == 0 {
			return allUsers
		}
		seen := make(map[string]bool)
		var result []string
		for u, groups := range userPerms {
			for _, g := range groups {
				if g.SudoCommands == "" {
					continue
				}
				h := strings.TrimSpace(g.SudoHosts)
				// Empty SudoHosts means no host restriction — treat as ALL
				if h == "" || h == "ALL" {
					if !seen[u] {
						seen[u] = true
						result = append(result, u)
					}
					break
				}
				for _, part := range strings.Split(h, ",") {
					if strings.TrimSpace(part) == hostname {
						if !seen[u] {
							seen[u] = true
							result = append(result, u)
						}
						break
					}
				}
			}
		}
		sort.Strings(result)
		return result
	}

	// Fetch group permissions from Pocket ID for per-host user lists
	var userPerms map[string][]pocketIDGroupInfo
	if s.pocketIDClient != nil {
		perms, err := s.pocketIDClient.GetUserPermissions()
		if err != nil {
			log.Printf("WARNING: fetching Pocket ID permissions for hosts: %v", err)
		} else {
			userPerms = perms
		}
	}
	allKnownUsers := s.store.AllUsers()

	// Collect all group names for the filter dropdown
	groupFilter := r.URL.Query().Get("group")
	groupSet := make(map[string]struct{})

	var hostViews []hostView
	for _, h := range hosts {
		hv := hostView{Hostname: h}

		// Build active session map for this host
		activeMap := make(map[string]string) // username -> remaining
		for _, sess := range s.store.ActiveSessionsForHost(h) {
			activeMap[sess.Username] = formatDuration(time.Until(sess.ExpiresAt))
		}

		// Build per-user rows from Pocket ID claims (or fallback to all known users)
		seen := make(map[string]bool)
		for _, u := range usersForHost(h, userPerms, allKnownUsers) {
			seen[u] = true
			remaining, active := activeMap[u]
			hv.HostUsers = append(hv.HostUsers, hostUserView{
				Username:  u,
				Active:    active,
				Remaining: remaining,
				Hostname:  h,
			})
		}
		// Always include users with active sessions, even if no longer in Pocket ID claims
		for u, remaining := range activeMap {
			if !seen[u] {
				hv.HostUsers = append(hv.HostUsers, hostUserView{
					Username:  u,
					Active:    true,
					Remaining: remaining,
					Hostname:  h,
				})
			}
		}
		sort.Slice(hv.HostUsers, func(i, j int) bool { return hv.HostUsers[i].Username < hv.HostUsers[j].Username })

		if escrowRecord, ok := escrowed[h]; ok {
			hv.Escrowed = true
			hv.EscrowAge = formatDuration(time.Since(escrowRecord.Timestamp))
			hv.EscrowExpired = time.Since(escrowRecord.Timestamp) > time.Duration(rotationDays)*24*time.Hour
			if s.cfg.EscrowLinkTemplate != "" {
				link := strings.ReplaceAll(s.cfg.EscrowLinkTemplate, "{hostname}", h)
				if escrowRecord.ItemID != "" {
					link = strings.ReplaceAll(link, "{item_id}", escrowRecord.ItemID)
				}
				hv.EscrowLink = link
			}
		}
		if _, group, _, ok := s.hostRegistry.GetHost(h); ok {
			hv.Group = group
		}
		if hv.Group != "" {
			groupSet[hv.Group] = struct{}{}
		}
		// Apply group filter if set
		if groupFilter != "" && hv.Group != groupFilter {
			continue
		}
		hostViews = append(hostViews, hv)
	}

	// Build sorted list of all known groups for the filter dropdown
	var allGroups []string
	for g := range groupSet {
		allGroups = append(allGroups, g)
	}
	sort.Strings(allGroups)

	now := time.Now()
	csrfTs := fmt.Sprintf("%d", now.Unix())
	csrfToken := computeCSRFToken(s.cfg.SharedSecret, username, csrfTs)

	// Build duration options, filtering to those <= GracePeriod
	type durationOption struct {
		Value    int
		Label    string
		Selected bool
	}
	allDurations := []durationOption{
		{3600, t("1_hour"), false},
		{14400, t("4_hours"), false},
		{28800, t("8_hours"), true},
		{86400, t("1_day"), false},
	}
	var durations []durationOption
	graceSec := int(s.cfg.GracePeriod.Seconds())
	if graceSec <= 0 {
		graceSec = 86400
	}
	for _, d := range allDurations {
		if d.Value <= graceSec {
			d.Selected = false
			durations = append(durations, d)
		}
	}
	if len(durations) > 0 {
		durations[len(durations)-1].Selected = true
	}
	if len(durations) == 0 && s.cfg.GracePeriod > 0 {
		durations = append(durations, durationOption{
			Value:    int(s.cfg.GracePeriod.Seconds()),
			Label:    formatDuration(s.cfg.GracePeriod),
			Selected: true,
		})
	}

	hostsTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, err := time.LoadLocation(c.Value); err == nil {
			hostsTZ = c.Value
		}
	}

	hasEscrowed := false
	for _, hv := range hostViews {
		if hv.Escrowed {
			hasEscrowed = true
			break
		}
	}

	w.Header().Set("Content-Type", "text/html")
	if err := adminTmpl.Execute(w, map[string]interface{}{
		"Username":         username,
		"Initial":          strings.ToUpper(username[:1]),
		"Avatar":           getAvatar(r),
		"Timezone":         hostsTZ,
		"Flashes":          flashes,
		"Hosts":            hostViews,
		"CSRFToken":        csrfToken,
		"CSRFTs":           csrfTs,
		"Durations":        durations,
		"ActivePage":       "admin",
		"AdminTab":         "hosts",
		"Theme":            getTheme(r),
		"CSPNonce":         r.Context().Value("csp-nonce"),
		"T":                T(lang),
		"Lang":             lang,
		"Languages":        supportedLanguages,
		"IsAdmin":          true,
		"EscrowLinkLabel":  s.cfg.EscrowLinkLabel,
		"HasEscrowedHosts": hasEscrowed,
		"AllGroups":        allGroups,
		"GroupFilter":      groupFilter,
	}); err != nil {
		log.Printf("ERROR: template execution: %v", err)
	}
}

func (s *Server) handleRemoveUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminUser := s.verifyFormAuth(w, r)
	if adminUser == "" {
		return
	}
	if s.getSessionRole(r) != "admin" {
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "not_authorized_message")
		return
	}
	targetUser := r.FormValue("target_user")
	if targetUser == "" || !validUsername.MatchString(targetUser) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}
	// Don't allow removing yourself
	if targetUser == adminUser {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}

	// Remove from host registry user lists
	if s.hostRegistry.IsEnabled() {
		s.hostRegistry.RemoveUserFromAllHosts(targetUser)
	}

	s.store.LogAction(targetUser, "user_removed", "", "", adminUser)
	s.store.RemoveUser(targetUser)
	log.Printf("USER_REMOVED: admin %q removed user %q from %s", adminUser, targetUser, remoteAddr(r))

	setFlashCookie(w, "removed_user:"+targetUser)
	http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/admin/users", http.StatusSeeOther)
}
