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
	http.Redirect(w, r, "/admin/history", http.StatusSeeOther)
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
		SudoSummary    string
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
		// Build deduplicated sudo summary
		var sudoRules []string
		seenRules := make(map[string]bool)
		for _, g := range uv.Groups {
			rule := g.SudoCommands
			if g.SudoHosts != "" && g.SudoHosts != "ALL" {
				rule += " on " + g.SudoHosts
			}
			if g.SudoRunAs != "" && g.SudoRunAs != "root" {
				rule += " as " + g.SudoRunAs
			}
			if !seenRules[rule] {
				sudoRules = append(sudoRules, rule)
				seenRules[rule] = true
			}
		}
		if len(sudoRules) > 0 {
			uv.SudoSummary = "Effective: " + strings.Join(sudoRules, "; ")
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

	// Parse flash messages from cookie
	var flashes []string
	if flashParam := getAndClearFlash(w, r); flashParam != "" {
		for _, f := range strings.Split(flashParam, ",") {
			parts := strings.SplitN(f, ":", 2)
			if len(parts) == 2 {
				switch parts[0] {
				case "elevated":
					flashes = append(flashes, t("elevated_session_on")+" "+parts[1])
				case "extended":
					flashes = append(flashes, t("extended_session_on")+" "+parts[1])
				case "extended_all":
					flashes = append(flashes, fmt.Sprintf(t("extended_n_sessions"), atoi(parts[1])))
				case "revoked":
					flashes = append(flashes, t("revoked_session_on")+" "+parts[1])
				case "revoked_all":
					flashes = append(flashes, fmt.Sprintf(t("revoked_n_sessions"), atoi(parts[1])))
				case "rotated":
					flashes = append(flashes, t("rotated_breakglass_on")+" "+parts[1])
				case "rotated_all":
					flashes = append(flashes, fmt.Sprintf(t("rotated_n_hosts"), atoi(parts[1])))
				}
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

	type activeUserView struct {
		Username  string
		Remaining string
		Hostname  string // for per-user action forms
	}

	type hostView struct {
		Hostname        string
		Active          bool
		ActiveUsers     []activeUserView
		Escrowed        bool
		EscrowAge       string
		EscrowExpired   bool
		EscrowLink      string
		Registered      bool
		AuthorizedUsers []string
		Group           string
	}

	// Collect all group names for the filter dropdown
	groupFilter := r.URL.Query().Get("group")
	groupSet := make(map[string]struct{})

	var hostViews []hostView
	for _, h := range hosts {
		hv := hostView{Hostname: h}
		var activeUsers []activeUserView
		for _, sess := range s.store.ActiveSessionsForHost(h) {
			activeUsers = append(activeUsers, activeUserView{
				Username:  sess.Username,
				Remaining: formatDuration(time.Until(sess.ExpiresAt)),
				Hostname:  h,
			})
		}
		hv.ActiveUsers = activeUsers
		hv.Active = len(activeUsers) > 0
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
		if users, group, _, ok := s.hostRegistry.GetHost(h); ok {
			hv.Registered = true
			hv.AuthorizedUsers = users
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

// handleAdminHistory renders the all-users history at /admin/history.
// GET /admin/history
func (s *Server) handleAdminHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Handle language change via query param
	if setLanguageCookie(w, r) {
		return
	}
	lang := detectLanguage(r)

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

	// Timezone handling
	tzName := "UTC"
	if tzParam := r.URL.Query().Get("tz"); tzParam != "" {
		if loc, err := time.LoadLocation(tzParam); err == nil {
			_ = loc
			tzName = tzParam
			http.SetCookie(w, &http.Cookie{
				Name:     "pam_tz",
				Value:    tzParam,
				Path:     "/",
				MaxAge:   86400,
				HttpOnly: false,
				SameSite: http.SameSiteLaxMode,
			})
		}
	} else if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if loc, err := time.LoadLocation(c.Value); err == nil {
			_ = loc
			tzName = c.Value
		}
	}
	tzLoc, _ := time.LoadLocation(tzName)

	query := r.URL.Query().Get("q")
	actionFilter := r.URL.Query().Get("action")
	hostFilter := r.URL.Query().Get("hostname")
	userFilter := r.URL.Query().Get("user")

	sortField := r.URL.Query().Get("sort")
	switch sortField {
	case "timestamp", "action", "hostname", "code", "user":
		// valid
	default:
		sortField = "timestamp"
	}
	sortOrder := r.URL.Query().Get("order")
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "desc"
	}

	page := 1
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 0 {
		page = p
	}

	perPage := s.cfg.DefaultHistoryPageSize
	if pp, err := strconv.Atoi(r.URL.Query().Get("per_page")); err == nil {
		validSizes := map[int]bool{5: true, 10: true, 25: true, 50: true, 100: true, 500: true, 1000: true}
		if validSizes[pp] {
			perPage = pp
		}
	}

	// All users history
	allHistory := s.store.AllActionHistoryWithUsers()

	// Collect unique values for filter dropdowns
	t := T(lang)
	actionSet := make(map[string]bool)
	hostSet := make(map[string]bool)
	userSet := make(map[string]bool)
	for _, e := range allHistory {
		actionSet[e.Action] = true
		if e.Hostname != "" {
			hostSet[e.Hostname] = true
		}
		userSet[e.Username] = true
	}

	var actionOptions []ActionOption
	actionOrder := []string{"approved", "auto_approved", "rejected", "revoked", "elevated", "extended", "rotated_breakglass"}
	for _, a := range actionOrder {
		if actionSet[a] {
			actionOptions = append(actionOptions, ActionOption{Value: a, Label: t(a)})
		}
	}
	for a := range actionSet {
		found := false
		for _, known := range actionOrder {
			if a == known {
				found = true
				break
			}
		}
		if !found {
			actionOptions = append(actionOptions, ActionOption{Value: a, Label: t(a)})
		}
	}

	var hostOptions []string
	for h := range hostSet {
		hostOptions = append(hostOptions, h)
	}
	sort.Strings(hostOptions)

	var userOptions []string
	for u := range userSet {
		userOptions = append(userOptions, u)
	}
	sort.Strings(userOptions)

	history := allHistory

	// Filter by user
	if userFilter != "" {
		var filtered []ActionLogEntryWithUser
		for _, e := range history {
			if e.Username == userFilter {
				filtered = append(filtered, e)
			}
		}
		history = filtered
	}

	// Filter by action type
	if actionFilter != "" {
		var filtered []ActionLogEntryWithUser
		for _, e := range history {
			if e.Action == actionFilter {
				filtered = append(filtered, e)
			}
		}
		history = filtered
	}

	// Filter by hostname
	if hostFilter != "" {
		var filtered []ActionLogEntryWithUser
		for _, e := range history {
			if e.Hostname == hostFilter {
				filtered = append(filtered, e)
			}
		}
		history = filtered
	}

	// Filter by search term
	if query != "" {
		q := strings.ToLower(query)
		var filtered []ActionLogEntryWithUser
		for _, e := range history {
			if strings.Contains(strings.ToLower(e.Hostname), q) ||
				strings.Contains(strings.ToLower(e.Code), q) ||
				strings.Contains(strings.ToLower(e.Username), q) {
				filtered = append(filtered, e)
			}
		}
		history = filtered
	}

	// Sort results
	asc := sortOrder == "asc"
	sort.SliceStable(history, func(i, j int) bool {
		switch sortField {
		case "action":
			if asc {
				return history[i].Action < history[j].Action
			}
			return history[i].Action > history[j].Action
		case "hostname":
			if asc {
				return history[i].Hostname < history[j].Hostname
			}
			return history[i].Hostname > history[j].Hostname
		case "code":
			if asc {
				return history[i].Code < history[j].Code
			}
			return history[i].Code > history[j].Code
		case "user":
			if asc {
				return history[i].Username < history[j].Username
			}
			return history[i].Username > history[j].Username
		default: // timestamp
			if asc {
				return history[i].Timestamp.Before(history[j].Timestamp)
			}
			return history[i].Timestamp.After(history[j].Timestamp)
		}
	})

	// Paginate
	totalPages := (len(history) + perPage - 1) / perPage
	if totalPages < 1 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}
	start := (page - 1) * perPage
	end := start + perPage
	if end > len(history) {
		end = len(history)
	}
	pageHistory := history[start:end]

	var viewEntries []historyViewEntry
	for _, e := range pageHistory {
		viewEntries = append(viewEntries, historyViewEntry{
			Action:        e.Action,
			ActionLabel:   t(e.Action),
			Hostname:      e.Hostname,
			Code:          e.Code,
			Actor:         e.Actor,
			Username:      e.Username,
			FormattedTime: e.Timestamp.In(tzLoc).Format("2006-01-02 15:04"),
			TimeAgo:       timeAgoI18n(e.Timestamp, t),
		})
	}

	perPageOptions := []int{5, 10, 25, 50, 100, 500, 1000}

	adminTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, err := time.LoadLocation(c.Value); err == nil {
			adminTZ = c.Value
		}
	}

	w.Header().Set("Content-Type", "text/html")
	if err := adminTmpl.Execute(w, map[string]interface{}{
		"Username":       username,
		"Initial":        strings.ToUpper(username[:1]),
		"Avatar":         getAvatar(r),
		"Timezone":       adminTZ,
		"ActivePage":     "admin",
		"AdminTab":       "history",
		"Theme":          getTheme(r),
		"CSPNonce":       r.Context().Value("csp-nonce"),
		"T":              T(lang),
		"Lang":           lang,
		"Languages":      supportedLanguages,
		"IsAdmin":        true,
		"History":        viewEntries,
		"Query":          query,
		"ActionFilter":   actionFilter,
		"HostFilter":     hostFilter,
		"UserFilter":     userFilter,
		"ActionOptions":  actionOptions,
		"HostOptions":    hostOptions,
		"UserOptions":    userOptions,
		"TZName":         tzName,
		"Page":           page,
		"TotalPages":     totalPages,
		"HasPrev":        page > 1,
		"HasNext":        page < totalPages,
		"Sort":           sortField,
		"Order":          sortOrder,
		"PerPage":        perPage,
		"PerPageOptions": perPageOptions,
	}); err != nil {
		log.Printf("ERROR: template execution: %v", err)
	}
}

// handleRemoveUser removes all data for a user.
// POST /api/users/remove
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
