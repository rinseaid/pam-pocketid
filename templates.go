package main

import (
	"fmt"
	"html/template"
	"time"
)

// templateFuncMap is the shared function map for all templates.
var templateFuncMap = template.FuncMap{
	"formatDuration": formatDuration,
	"timeAgo":        timeAgo,
	"formatTime":     formatTime,
	"eq":             func(a, b string) bool { return a == b },
	"eqInt":          func(a, b int) bool { return a == b },
	"add":            func(a, b int) int { return a + b },
	"sub":            func(a, b int) int { return a - b },
}

// Pre-parsed templates — avoids re-parsing on every request.
var (
	approvalAlreadyTmpl = template.Must(template.New("already").Parse(approvalAlreadyHTML))
	approvalExpiredTmpl = template.Must(template.New("expired").Parse(approvalExpiredHTML))
	adminTmpl           = template.Must(template.New("admin").Funcs(templateFuncMap).Parse(adminPageHTML))
	dashboardTmpl       = template.Must(template.New("dashboard").Funcs(templateFuncMap).Parse(dashboardHTML))
	historyTmpl         = template.Must(template.New("history").Funcs(templateFuncMap).Parse(historyPageHTML))
)
// HTML templates
// All user-controlled values are rendered via html/template (auto-escaped).
// Templates share a common CSS design system with dark mode support via
// CSS custom properties and @media (prefers-color-scheme: dark).

// sharedCSS is the common design system embedded in every template.
// Uses CSS custom properties for dark mode, Inter/system font stack,
// and professional styling inspired by Pocket ID / Tinyauth.
const sharedCSS = `
    :root {
      --bg: #f3f4f6;
      --card-bg: #ffffff;
      --text: #111827;
      --text-secondary: #6b7280;
      --border: #e5e7eb;
      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --primary-text: #ffffff;
      --success: #059669;
      --success-bg: #ecfdf5;
      --success-border: #a7f3d0;
      --danger: #dc2626;
      --danger-bg: #fef2f2;
      --danger-border: #fecaca;
      --warning: #d97706;
      --warning-bg: #fffbeb;
      --warning-border: #fde68a;
      --info-bg: #eff6ff;
      --info-border: #bfdbfe;
      --code-bg: #f9fafb;
      --code-border: #d1d5db;
      --shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 24px rgba(0,0,0,0.05);
      --focus-ring: 0 0 0 3px rgba(59,130,246,0.4);
      --terminal-bg: #1a1a2e;
      --terminal-text: #c8f0c8;
      --chip-cmd-bg: rgba(59,130,246,0.12); --chip-cmd-border: rgba(59,130,246,0.25);
      --chip-host-bg: rgba(16,185,129,0.12); --chip-host-border: rgba(16,185,129,0.25);
      --chip-all-bg: rgba(99,102,241,0.12); --chip-all-text: #6366f1; --chip-all-border: rgba(99,102,241,0.25);
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #0f172a;
        --card-bg: #1e293b;
        --text: #f1f5f9;
        --text-secondary: #94a3b8;
        --border: #334155;
        --primary: #60a5fa;
        --primary-hover: #3b82f6;
        --primary-text: #0f172a;
        --success: #34d399;
        --success-bg: #064e3b;
        --success-border: #065f46;
        --danger: #f87171;
        --danger-bg: #450a0a;
        --danger-border: #7f1d1d;
        --warning: #fbbf24;
        --warning-bg: #451a03;
        --warning-border: #78350f;
        --info-bg: #1e3a5f;
        --info-border: #1e40af;
        --code-bg: #0f172a;
        --code-border: #475569;
        --shadow: 0 1px 3px rgba(0,0,0,0.3), 0 4px 24px rgba(0,0,0,0.2);
        --terminal-bg: #1a1a2e;
        --terminal-text: #c8f0c8;
        --chip-cmd-bg: rgba(96,165,250,0.12); --chip-cmd-border: rgba(96,165,250,0.25);
        --chip-host-bg: rgba(52,211,153,0.12); --chip-host-border: rgba(52,211,153,0.25);
        --chip-all-bg: rgba(129,140,248,0.12); --chip-all-text: #818cf8; --chip-all-border: rgba(129,140,248,0.25);
      }
      .approve-btn { color: #022c22; }
    }
    .theme-light {
      --bg: #f3f4f6;
      --card-bg: #ffffff;
      --text: #111827;
      --text-secondary: #6b7280;
      --border: #e5e7eb;
      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --primary-text: #ffffff;
      --success: #059669;
      --success-bg: #ecfdf5;
      --success-border: #a7f3d0;
      --danger: #dc2626;
      --danger-bg: #fef2f2;
      --danger-border: #fecaca;
      --warning: #d97706;
      --warning-bg: #fffbeb;
      --warning-border: #fde68a;
      --info-bg: #eff6ff;
      --info-border: #bfdbfe;
      --code-bg: #f9fafb;
      --code-border: #d1d5db;
      --shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 24px rgba(0,0,0,0.05);
      --focus-ring: 0 0 0 3px rgba(59,130,246,0.4);
      --terminal-bg: #1a1a2e;
      --terminal-text: #c8f0c8;
      --chip-cmd-bg: rgba(59,130,246,0.12); --chip-cmd-border: rgba(59,130,246,0.25);
      --chip-host-bg: rgba(16,185,129,0.12); --chip-host-border: rgba(16,185,129,0.25);
      --chip-all-bg: rgba(99,102,241,0.12); --chip-all-text: #6366f1; --chip-all-border: rgba(99,102,241,0.25);
    }
    .theme-dark {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --text: #f1f5f9;
      --text-secondary: #94a3b8;
      --border: #334155;
      --primary: #60a5fa;
      --primary-hover: #3b82f6;
      --primary-text: #0f172a;
      --success: #34d399;
      --success-bg: #064e3b;
      --success-border: #065f46;
      --danger: #f87171;
      --danger-bg: #450a0a;
      --danger-border: #7f1d1d;
      --warning: #fbbf24;
      --warning-bg: #451a03;
      --warning-border: #78350f;
      --info-bg: #1e3a5f;
      --info-border: #1e40af;
      --code-bg: #0f172a;
      --code-border: #475569;
      --shadow: 0 1px 3px rgba(0,0,0,0.3), 0 4px 24px rgba(0,0,0,0.2);
      --focus-ring: 0 0 0 3px rgba(96,165,250,0.4);
      --terminal-bg: #1a1a2e;
      --terminal-text: #c8f0c8;
      --chip-cmd-bg: rgba(96,165,250,0.12); --chip-cmd-border: rgba(96,165,250,0.25);
      --chip-host-bg: rgba(52,211,153,0.12); --chip-host-border: rgba(52,211,153,0.25);
      --chip-all-bg: rgba(129,140,248,0.12); --chip-all-text: #818cf8; --chip-all-border: rgba(129,140,248,0.25);
    }
    .theme-dark .approve-btn { color: #022c22; }
    *, *::before, *::after { box-sizing: border-box; }
    @media (min-width: 768px) {
      body.wide { max-width: 960px; }
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', Roboto, sans-serif;
      max-width: 440px;
      margin: 0 auto;
      padding: 48px 20px;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      -webkit-font-smoothing: antialiased;
    }
    .card {
      background: var(--card-bg);
      border-radius: 16px;
      padding: 40px 32px;
      box-shadow: var(--shadow);
      border: 1px solid var(--border);
      width: 100%;
      text-align: center;
    }
    h2 {
      font-size: 1.375rem;
      font-weight: 700;
      margin: 12px 0 8px;
      letter-spacing: -0.01em;
    }
    p { margin: 8px 0; color: var(--text-secondary); font-size: 0.938rem; }
    .icon {
      width: 56px;
      height: 56px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 8px;
      font-size: 1.5rem;
    }
    strong { color: var(--text); font-weight: 600; }
`

// formatTime formats a time as "2006-01-02 15:04 UTC".
func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04") + " UTC"
}


// timeAgo formats a time as a human-readable relative string like "2m ago" or "1h ago".
func timeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// timeAgoI18n formats a time as a localized human-readable relative string.
func timeAgoI18n(when time.Time, t func(string) string) string {
	d := time.Since(when)
	switch {
	case d < time.Minute:
		return t("just_now")
	case d < time.Hour:
		return fmt.Sprintf("%d%s %s", int(d.Minutes()), t("minute_abbr"), t("ago"))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d%s %s", int(d.Hours()), t("hour_abbr"), t("ago"))
	default:
		return fmt.Sprintf("%d%s %s", int(d.Hours()/24), t("day_abbr"), t("ago"))
	}
}

// historyViewEntry is a pre-formatted history entry for the template.
type historyViewEntry struct {
	Action        string
	ActionLabel   string
	Hostname      string
	Code          string
	Actor         string
	Username      string
	FormattedTime string
	TimeAgo       string
}

// timelineEntry represents one hour-slot in the 24-hour activity timeline.
type timelineEntry struct {
	Hour      int
	HourLabel string // "14:00"
	Count     int
	Height    int // bar height in pixels (2-40)
	IsNow     bool
	HoursAgo  int    // offset from now (0 = current hour)
	Details   string // rich tooltip text
}

// ActionOption represents a value/label pair for dropdown select options.
type ActionOption struct {
	Value string
	Label string
}


// navCSS is the shared navigation bar styles used across dashboard, history, and hosts pages.
const navCSS = `
    .nav { display: flex; gap: 8px; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--border); justify-content: center; align-items: center; flex-wrap: wrap; }
    .nav a { color: var(--text-secondary); text-decoration: none; font-size: 0.875rem; font-weight: 500; padding: 4px 8px; border-radius: 6px; }
    .nav a:hover { color: var(--text); background: var(--info-bg); }
    .nav a.active { color: var(--primary); font-weight: 700; }
    .theme-options { display: flex; gap: 4px; padding: 4px 12px 8px; }
    .theme-option { flex: 1; text-align: center; padding: 5px 8px; border-radius: 6px; font-size: 0.75rem; color: var(--text); text-decoration: none; border: 1px solid var(--border); cursor: pointer; font-weight: 500; }
    .theme-option:hover { background: var(--info-bg); }
    .theme-option.active { background: var(--primary); color: var(--primary-text); border-color: var(--primary); font-weight: 600; }
    .profile-menu { position: relative; }
    .profile-btn {
      width: 32px; height: 32px; border-radius: 50%;
      background: var(--primary); color: var(--primary-text);
      display: flex; align-items: center; justify-content: center;
      font-weight: 700; font-size: 0.813rem; cursor: pointer;
      border: none; text-decoration: none;
    }
    .profile-btn:hover { opacity: 0.9; }
    .profile-img { width: 32px; height: 32px; border-radius: 50%; object-fit: cover; }
    .profile-dropdown {
      display: none;
      position: absolute; right: 0; top: 40px;
      background: var(--card-bg); border: 1px solid var(--border);
      border-radius: 10px; box-shadow: var(--shadow);
      min-width: 220px; padding: 12px 0; z-index: 100;
    }
    .profile-menu:focus-within .profile-dropdown { display: block; }
    .profile-dropdown-item {
      display: block; padding: 8px 16px; color: var(--text);
      text-decoration: none; font-size: 0.875rem;
    }
    .profile-dropdown-item:hover { background: var(--info-bg); }
    .profile-dropdown-divider { border-top: 1px solid var(--border); margin: 8px 0; }
    .admin-pill { display: inline-block; font-size: 0.6rem; padding: 2px 8px; border-radius: 10px; background: var(--primary); color: var(--primary-text); font-weight: 600; letter-spacing: 0.03em; text-transform: uppercase; vertical-align: middle; margin-left: 6px; }
    .profile-dropdown-label {
      padding: 4px 16px; font-size: 0.75rem; color: var(--text-secondary);
      font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;
    }
    .profile-dropdown select {
      margin: 4px 16px; padding: 4px 8px; border: 1px solid var(--border);
      border-radius: 6px; font-size: 0.813rem; background: var(--card-bg); color: var(--text);
      width: calc(100% - 32px);
    }
`

// tzOptionsHTML is the timezone <option> list reused in the profile dropdown across all pages.
const tzOptionsHTML = `
    <option value="UTC" {{if eq .Timezone "UTC"}}selected{{end}}>UTC</option>
    <optgroup label="Americas">
      <option value="Pacific/Honolulu" {{if eq .Timezone "Pacific/Honolulu"}}selected{{end}}>UTC-10 (Hawaii)</option>
      <option value="America/Anchorage" {{if eq .Timezone "America/Anchorage"}}selected{{end}}>UTC-9 (Alaska)</option>
      <option value="America/Los_Angeles" {{if eq .Timezone "America/Los_Angeles"}}selected{{end}}>UTC-8 (Los Angeles, Vancouver)</option>
      <option value="America/Denver" {{if eq .Timezone "America/Denver"}}selected{{end}}>UTC-7 (Denver, Phoenix)</option>
      <option value="America/Chicago" {{if eq .Timezone "America/Chicago"}}selected{{end}}>UTC-6 (Chicago, Mexico City)</option>
      <option value="America/New_York" {{if eq .Timezone "America/New_York"}}selected{{end}}>UTC-5 (New York, Toronto)</option>
      <option value="America/Halifax" {{if eq .Timezone "America/Halifax"}}selected{{end}}>UTC-4 (Halifax, Bermuda)</option>
      <option value="America/St_Johns" {{if eq .Timezone "America/St_Johns"}}selected{{end}}>UTC-3:30 (Newfoundland)</option>
      <option value="America/Sao_Paulo" {{if eq .Timezone "America/Sao_Paulo"}}selected{{end}}>UTC-3 (São Paulo, Buenos Aires)</option>
    </optgroup>
    <optgroup label="Europe &amp; Africa">
      <option value="Atlantic/Reykjavik" {{if eq .Timezone "Atlantic/Reykjavik"}}selected{{end}}>UTC+0 (Reykjavik)</option>
      <option value="Europe/London" {{if eq .Timezone "Europe/London"}}selected{{end}}>UTC+0 (London, Dublin)</option>
      <option value="Europe/Paris" {{if eq .Timezone "Europe/Paris"}}selected{{end}}>UTC+1 (Paris, Berlin, Amsterdam)</option>
      <option value="Europe/Helsinki" {{if eq .Timezone "Europe/Helsinki"}}selected{{end}}>UTC+2 (Helsinki, Cairo, Johannesburg)</option>
      <option value="Europe/Moscow" {{if eq .Timezone "Europe/Moscow"}}selected{{end}}>UTC+3 (Moscow, Istanbul, Nairobi)</option>
    </optgroup>
    <optgroup label="Asia &amp; Pacific">
      <option value="Asia/Dubai" {{if eq .Timezone "Asia/Dubai"}}selected{{end}}>UTC+4 (Dubai, Baku)</option>
      <option value="Asia/Kolkata" {{if eq .Timezone "Asia/Kolkata"}}selected{{end}}>UTC+5:30 (Mumbai, New Delhi)</option>
      <option value="Asia/Dhaka" {{if eq .Timezone "Asia/Dhaka"}}selected{{end}}>UTC+6 (Dhaka, Almaty)</option>
      <option value="Asia/Bangkok" {{if eq .Timezone "Asia/Bangkok"}}selected{{end}}>UTC+7 (Bangkok, Jakarta)</option>
      <option value="Asia/Shanghai" {{if eq .Timezone "Asia/Shanghai"}}selected{{end}}>UTC+8 (Shanghai, Singapore, Perth)</option>
      <option value="Asia/Tokyo" {{if eq .Timezone "Asia/Tokyo"}}selected{{end}}>UTC+9 (Tokyo, Seoul)</option>
      <option value="Australia/Sydney" {{if eq .Timezone "Australia/Sydney"}}selected{{end}}>UTC+10 (Sydney, Melbourne)</option>
      <option value="Pacific/Auckland" {{if eq .Timezone "Pacific/Auckland"}}selected{{end}}>UTC+12 (Auckland, Fiji)</option>
    </optgroup>`

const dashboardHTML = `<!DOCTYPE html>
<html lang="{{.Lang}}" class="{{if eq .Theme "dark"}}theme-dark{{else if eq .Theme "light"}}theme-light{{end}}">
<head>
  <title>{{call .T "sessions"}} - {{call .T "app_name"}}</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>` + sharedCSS + navCSS + `
    body { align-items: flex-start; padding-top: 32px; }
    .section-label {
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-secondary);
      margin: 24px 0 8px;
      text-align: left;
    }
    .section-label.pending { color: var(--warning); }
    .list { text-align: left; margin: 0 0 8px; }
    .row { display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid var(--border); gap: 12px; border-left: 3px solid transparent; padding-left: 10px; margin-left: -13px; }
    .row.row-active { border-left-color: var(--primary); }
    .row-info { min-width: 0; flex: 1; }
    .row-host { font-weight: 600; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .row-sub { color: var(--text-secondary); font-size: 0.813rem; display: block; }
    .row-label { font-size: 0.65rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-secondary); opacity: 0.55; }
    .host-access-header { display: flex; align-items: center; justify-content: space-between; }
    .toggle-wrap { display: flex; align-items: center; gap: 8px; cursor: pointer; user-select: none; }
    .toggle-wrap span { font-size: 0.7rem; font-weight: 600; color: var(--text-secondary); }
    .toggle-track { width: 44px; height: 26px; border-radius: 13px; background: var(--border); position: relative; transition: background 0.2s; flex-shrink: 0; }
    .toggle-thumb { width: 20px; height: 20px; border-radius: 50%; background: var(--card-bg); box-shadow: 0 1px 3px rgba(0,0,0,0.3); position: absolute; top: 3px; left: 3px; transition: left 0.2s; }
    .toggle-wrap.active .toggle-track { background: var(--primary); }
    .toggle-wrap.active .toggle-thumb { left: 21px; }
    .list.active-only [data-active="false"] { display: none; }
    .row-value { color: var(--text); font-weight: 500; }
    .row-code { color: var(--text-secondary); font-size: 0.813rem; font-family: monospace; display: block; }
    .banner { padding: 10px 16px; border-radius: 8px; margin-bottom: 12px; font-size: 0.875rem; font-weight: 600; text-align: left; }
    .banner-success { background: var(--success-bg); border: 1px solid var(--success-border); color: var(--success); }
    .approve-btn { background: var(--success); border: none; color: #fff; padding: 6px 12px; border-radius: 8px; cursor: pointer; font-size: 0.813rem; font-weight: 600; min-height: 32px; white-space: nowrap; flex-shrink: 0; }
    .approve-btn:focus-visible { outline: none; box-shadow: 0 0 0 3px rgba(5,150,105,0.4); }
    .approve-btn:hover { opacity: 0.9; }
    .host-btn { display: inline-block; padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 0.75rem; font-weight: 600; white-space: nowrap; border: 1px solid var(--border); background: none; color: var(--text-secondary); text-decoration: none; text-align: center; line-height: 1.4; }
    .host-btn:hover { background: var(--info-bg); color: var(--text); }
    .host-btn.danger { border-color: var(--danger); color: var(--danger); }
    .host-btn.danger:hover { background: var(--danger-bg); }
    .host-btn.primary { border-color: var(--primary); color: var(--primary); }
    .host-btn.primary:hover { background: var(--info-bg); }
    .bulk-actions { margin-top: 8px; text-align: right; }
    .bulk-btn { display: inline-block; background: none; border: 1px solid var(--border); color: var(--text-secondary); padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 0.75rem; font-weight: 600; }
    .bulk-btn:hover { background: var(--info-bg); color: var(--text); }
    .bulk-btn.success { border-color: var(--success); color: var(--success); }
    .admin-required { font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; background: var(--warning-bg); color: var(--warning); border: 1px solid var(--warning-border); white-space: nowrap; }
    .bulk-btn.success:hover { background: var(--success-bg); }
    .bulk-btn.primary { border-color: var(--primary); color: var(--primary); }
    .bulk-btn.primary:hover { background: var(--info-bg); }
    .bulk-btn.danger { border-color: var(--danger-border); color: var(--danger); }
    .bulk-btn.danger:hover { background: var(--danger-bg); }
    .history-entry { display: flex; align-items: center; gap: 10px; padding: 8px 0; border-bottom: 1px solid var(--border); }
    .history-action { font-size: 0.69rem; font-weight: 700; padding: 2px 7px; border-radius: 4px; white-space: nowrap; flex-shrink: 0; letter-spacing: 0.03em; text-transform: uppercase; }
    .history-action.approved { background: rgba(72,199,142,0.15); color: var(--success); }
    .history-action.auto_approved, .history-action.extended, .history-action.elevated { background: var(--info-bg); color: var(--primary); }
    .history-action.revoked, .history-action.rejected { background: var(--danger-bg); color: var(--danger); }
    .history-action.rotated_breakglass { border: 1px solid var(--border); color: var(--text-secondary); }
    .history-time { font-size: 0.75rem; color: var(--text-secondary); white-space: nowrap; flex-shrink: 0; min-width: 56px; }
    .history-host { color: var(--text); font-size: 0.813rem; flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .history-actor { font-size: 0.75rem; color: var(--text-secondary); white-space: nowrap; flex-shrink: 0; }
    .seg-btn { display: inline-flex; border-radius: 6px; overflow: hidden; border: 1px solid var(--primary); flex-shrink: 0; }
    .seg-btn button { background: none; border: none; border-right: 1px solid var(--primary); padding: 6px 9px; cursor: pointer; color: var(--primary); font-size: 0.75rem; font-weight: 600; font-family: inherit; line-height: 1.4; }
    .seg-btn button:last-child { border-right: none; }
    .seg-btn button:hover { background: var(--primary); color: var(--bg); }
    .empty-state { color: var(--text-secondary); margin: 16px 0; font-size: 0.875rem; }
    .view-all { display: block; text-align: left; margin-top: 8px; font-size: 0.813rem; color: var(--primary); text-decoration: none; font-weight: 600; }
    .view-all:hover { text-decoration: underline; }
  </style>
  <script nonce="{{.CSPNonce}}">
  if(!document.cookie.split(';').some(function(c){return c.trim().indexOf('pam_tz=')===0;})){
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    if(tz){var d=new Date();d.setTime(d.getTime()+86400000);document.cookie='pam_tz='+tz+';path=/;expires='+d.toUTCString()+';SameSite=Lax';}
  }
  document.addEventListener('DOMContentLoaded',function(){
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    document.querySelectorAll('.col-filter-select,.page-size-select,.tz-select,.lang-select').forEach(function(el){el.addEventListener('change',function(){this.form.submit();});});
    // Select the detected TZ in all tz-select dropdowns
    document.querySelectorAll('.tz-select').forEach(function(sel){
      for(var i=0;i<sel.options.length;i++){if(sel.options[i].value===tz){sel.selectedIndex=i;break;}}
    });
    // Profile dropdown toggle
    document.querySelectorAll('.profile-btn').forEach(function(btn){
      btn.addEventListener('click',function(e){
        var menu=btn.closest('.profile-menu');
        var dropdown=menu.querySelector('.profile-dropdown');
        var expanded=dropdown.style.display==='block';
        dropdown.style.display=expanded?'none':'block';
        btn.setAttribute('aria-expanded',!expanded);
        e.stopPropagation();
      });
    });
    document.addEventListener('click',function(){
      document.querySelectorAll('.profile-dropdown').forEach(function(d){d.style.display='none';});
      document.querySelectorAll('.profile-btn').forEach(function(b){b.setAttribute('aria-expanded','false');});
    });
    // Active-only filter toggle
    var filterBtn=document.getElementById('active-filter-btn');
    var hostList=document.getElementById('host-access-list');
    if(filterBtn&&hostList){
      var activeOnly=localStorage.getItem('pam_active_only')==='1';
      function applyFilter(){
        hostList.classList.toggle('active-only',activeOnly);
        filterBtn.classList.toggle('active',activeOnly);
        filterBtn.setAttribute('aria-checked',activeOnly);
      }
      applyFilter();
      filterBtn.addEventListener('click',function(){activeOnly=!activeOnly;localStorage.setItem('pam_active_only',activeOnly?'1':'0');applyFilter();});
      filterBtn.addEventListener('keydown',function(e){if(e.key===' '||e.key==='Enter'){e.preventDefault();activeOnly=!activeOnly;localStorage.setItem('pam_active_only',activeOnly?'1':'0');applyFilter();}});
    }
  });
  var es = new EventSource('/api/events');
  es.addEventListener('update', function(e) {
    location.reload();
  });
  es.onerror = function() {
    // Reconnect happens automatically via EventSource
    // Fallback: reload after 60s if disconnected
    setTimeout(function() { if (es.readyState === 2) location.reload(); }, 60000);
  };
  </script>
</head>
<body class="wide">
  <div class="card">
    <h2>{{call .T "app_name"}}</h2>

    <nav class="nav">
      <a href="/" class="{{if eq .ActivePage "access"}}active{{end}}">{{call .T "access"}}</a>
      <a href="/history" class="{{if eq .ActivePage "history"}}active{{end}}">{{call .T "history"}}</a>
      {{if .IsAdmin}}<a href="/admin" class="{{if eq .ActivePage "admin"}}active{{end}}">{{call .T "admin"}}</a>{{end}}
      <div class="profile-menu" tabindex="-1">
        <button class="profile-btn" type="button" aria-label="{{call .T "aria_user_menu"}}" aria-expanded="false" aria-haspopup="true">{{if .Avatar}}<img src="{{.Avatar}}" class="profile-img" alt="">{{else}}{{.Initial}}{{end}}</button>
        <div class="profile-dropdown">
          <div class="profile-dropdown-label">{{.Username}}{{if .IsAdmin}} <span class="admin-pill">{{call .T "admin"}}</span>{{end}}</div>
          <div class="profile-dropdown-divider"></div>
          <div class="profile-dropdown-label">{{call .T "language"}}</div>
          <form method="GET" action="/">
            <select name="lang" class="lang-select" aria-label="{{call .T "language"}}">
              {{range .Languages}}<option value="{{.Code}}" {{if eq .Code $.Lang}}selected{{end}}>{{.Name}}</option>{{end}}
            </select>
          </form>
          <div class="profile-dropdown-divider"></div>
          <div class="profile-dropdown-label">{{call .T "timezone"}}</div>
          <form method="GET" action="/">
            <select name="tz" class="tz-select" aria-label="{{call .T "timezone"}}">` + tzOptionsHTML + `
            </select>
          </form>
          <div class="profile-dropdown-divider"></div>
          <div class="profile-dropdown-label">{{call .T "theme"}}</div>
          <div class="theme-options">
            <a href="/theme?set=system&from=/" class="theme-option{{if eq .Theme ""}} active{{end}}">{{call .T "theme_system"}}</a>
            <a href="/theme?set=dark&from=/" class="theme-option{{if eq .Theme "dark"}} active{{end}}">{{call .T "theme_dark"}}</a>
            <a href="/theme?set=light&from=/" class="theme-option{{if eq .Theme "light"}} active{{end}}">{{call .T "theme_light"}}</a>
          </div>
          <div class="profile-dropdown-divider"></div>
          <a href="/signout" class="profile-dropdown-item" style="color:var(--danger)">{{call .T "sign_out"}}</a>
        </div>
      </div>
    </nav>

    {{range .Flashes}}<div class="banner banner-success" role="alert">{{.}}</div>{{end}}

    {{if .Pending}}
    <div class="section-label pending">{{call .T "pending_requests"}}</div>
    <div class="list" role="list" aria-label="{{call .T "pending_requests"}}">
      {{range .Pending}}
      <div class="row" role="listitem">
        <div class="row-info">
          <span class="row-host">{{.Hostname}}</span>
          {{if $.IsAdmin}}<span class="row-sub" style="color:var(--primary)">{{.Username}}</span>{{end}}
          {{if .AdminRequired}}<span class="admin-required">&#x1F512; {{call $.T "admin_approval_required"}}</span>{{end}}
          <span class="row-code">{{.Code}}</span>
          <span class="row-sub">{{call $.T "expires_in"}} {{.ExpiresIn}}</span>
        </div>
        <div style="display: flex; gap: 8px; flex-shrink: 0;">
          {{if not .AdminRequired}}
          <form method="POST" action="/api/challenges/approve">
            <input type="hidden" name="challenge_id" value="{{.ID}}">
            <input type="hidden" name="username" value="{{$.Username}}">
            <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
            <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
            <button type="submit" class="approve-btn" aria-label="{{call $.T "approve"}} {{.Hostname}}">{{call $.T "approve"}}</button>
          </form>
          {{else if $.IsAdmin}}
          <form method="POST" action="/api/challenges/approve">
            <input type="hidden" name="challenge_id" value="{{.ID}}">
            <input type="hidden" name="username" value="{{$.Username}}">
            <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
            <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
            <button type="submit" class="approve-btn" aria-label="{{call $.T "approve"}} {{.Hostname}}">{{call $.T "approve"}}</button>
          </form>
          {{end}}
          <form method="POST" action="/api/challenges/reject">
            <input type="hidden" name="challenge_id" value="{{.ID}}">
            <input type="hidden" name="username" value="{{$.Username}}">
            <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
            <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
            <button type="submit" class="host-btn danger" aria-label="{{call $.T "reject"}} {{.Hostname}}">{{call $.T "reject"}}</button>
          </form>
        </div>
      </div>
      {{end}}
    </div>
    <div style="display: flex; gap: 8px; justify-content: flex-end; margin-top: 8px;">
      <form method="POST" action="/api/challenges/approve-all" style="display:inline">
        <input type="hidden" name="username" value="{{.Username}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
        <button type="submit" class="bulk-btn success" onclick="return confirm('{{call .T "confirm_approve_all"}}')">{{call .T "approve_all"}}</button>
      </form>
      <form method="POST" action="/api/challenges/reject-all" style="display:inline">
        <input type="hidden" name="username" value="{{.Username}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
        <button type="submit" class="bulk-btn danger" onclick="return confirm('{{call .T "confirm_reject_all"}}')">{{call .T "reject_all"}}</button>
      </form>
    </div>
    {{end}}

    {{if .HostAccess}}
    <div class="host-access-header">
      <div class="section-label" style="margin-bottom:0">{{call .T "sudo_access"}}</div>
      {{if .HasActiveSessions}}<div class="toggle-wrap" id="active-filter-btn" role="switch" aria-checked="false" tabindex="0" aria-label="{{call .T "active_only"}}"><span>{{call .T "active_only"}}</span><div class="toggle-track"><div class="toggle-thumb"></div></div></div>{{end}}
    </div>
    <div class="list" id="host-access-list" role="list" aria-label="{{call .T "sudo_access"}}">
      {{range .HostAccess}}
      <div class="row{{if .Active}} row-active{{end}}" data-active="{{.Active}}" role="listitem">
        <div class="row-info">
          <span class="row-sub"><span class="row-label">{{call $.T "host"}}:</span> <span class="row-value">{{.Hostname}}</span></span>
          {{if .Active}}
            <span class="row-sub"><span class="row-label">{{call $.T "time_remaining"}}:</span> <span class="row-value">{{.Remaining}}</span></span>
          {{else}}
            <span class="row-sub">{{call $.T "no_sudo_session"}}</span>
          {{end}}
          {{if .SudoSummary}}<span class="row-sub"><span class="row-label">{{call $.T "commands"}}:</span> <span class="row-value">{{.SudoSummary}}</span></span>{{end}}
        </div>
        {{if .Active}}
        <form method="POST" action="/api/sessions/extend" style="display:inline">
          <input type="hidden" name="hostname" value="{{.Hostname}}">
          <input type="hidden" name="username" value="{{$.Username}}">
          <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
          <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
          <button type="submit" class="host-btn primary" onclick="return confirm('{{printf (call $.T "confirm_extend_session") .Hostname}}')">{{call $.T "extend"}}</button>
        </form>
        <form method="POST" action="/api/sessions/revoke">
          <input type="hidden" name="hostname" value="{{.Hostname}}">
          <input type="hidden" name="username" value="{{$.Username}}">
          <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
          <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
          <button type="submit" class="host-btn danger" aria-label="{{call $.T "revoke"}} {{.Hostname}}" onclick="return confirm('{{printf (call $.T "confirm_revoke_session") .Hostname}}')">{{call $.T "revoke"}}</button>
        </form>
        {{else}}
        <form method="POST" action="/api/hosts/elevate">
          <input type="hidden" name="hostname" value="{{.Hostname}}">
          <input type="hidden" name="username" value="{{$.Username}}">
          <input type="hidden" name="target_user" value="{{$.Username}}">
          <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
          <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
          <input type="hidden" name="from" value="/">
          <div class="seg-btn" role="group" aria-label="{{call $.T "elevate"}}">
            {{range $.Durations}}<button type="submit" name="duration" value="{{.Value}}">{{.Label}}</button>{{end}}
          </div>
        </form>
        {{end}}
      </div>
      {{end}}
    </div>
    {{if .HasActiveSessions}}
    <div class="bulk-actions">
      <form method="POST" action="/api/sessions/extend-all" style="display:inline">
        <input type="hidden" name="username" value="{{.Username}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
        <button type="submit" class="bulk-btn primary" onclick="return confirm('{{call .T "confirm_extend_all"}}')">{{call .T "extend_all"}}</button>
      </form>
      <form method="POST" action="/api/sessions/revoke-all" style="display:inline">
        <input type="hidden" name="username" value="{{.Username}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
        <button type="submit" class="bulk-btn danger" onclick="return confirm('{{call .T "confirm_revoke_all"}}')">{{call .T "revoke_all"}}</button>
      </form>
    </div>
    {{end}}
    {{end}}

    {{if not .Pending}}{{if not .HostAccess}}
    <p class="empty-state">{{call .T "no_host_access"}}</p>
    {{end}}{{end}}

    {{if .History}}
    <div class="section-label">{{call .T "recent_activity"}}</div>
    <div class="list">
      {{range .History}}
      <div class="history-entry">
        <span class="history-time">{{timeAgo .Timestamp}}</span>
        <span class="history-action {{.Action}}">{{if eq .Action "auto_approved"}}{{call $.T "auto_approved"}}{{else if eq .Action "approved"}}{{call $.T "approved"}}{{else if eq .Action "revoked"}}{{call $.T "revoked"}}{{else if eq .Action "rejected"}}{{call $.T "rejected"}}{{else if eq .Action "elevated"}}{{call $.T "elevated"}}{{else if eq .Action "extended"}}{{call $.T "extended"}}{{else if eq .Action "rotated_breakglass"}}{{call $.T "rotated_breakglass"}}{{else}}{{.Action}}{{end}}</span>
        <span class="history-host">{{.Hostname}}</span>
        {{if .Actor}}<span class="history-actor">{{call $.T "by"}} {{.Actor}}</span>{{end}}
      </div>
      {{end}}
    </div>
    {{if .HasMoreHistory}}<a href="/history" class="view-all">{{call .T "view_all_activity"}} &rarr;</a>{{end}}
    {{end}}
  </div>
</body>
</html>`

const historyPageHTML = `<!DOCTYPE html>
<html lang="{{.Lang}}" class="{{if eq .Theme "dark"}}theme-dark{{else if eq .Theme "light"}}theme-light{{end}}">
<head>
  <title>{{call .T "history"}} - {{call .T "app_name"}}</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="240">
  <style>` + sharedCSS + navCSS + `
    body { align-items: flex-start; padding-top: 32px; }
    .history-action { font-weight: 600; }
    .history-action.approved { color: var(--success); }
    .history-action.revoked { color: var(--danger); }
    .history-action.auto_approved { color: var(--primary); }
    .history-action.rejected { color: var(--danger); }
    .history-action.elevated { color: var(--primary); }
    .history-action.extended { color: var(--primary); }
    .history-action.rotated_breakglass { color: var(--text-secondary); }
    .history-actor { font-size: 0.7rem; color: var(--text-secondary); font-weight: 400; }
    .empty-state { color: var(--text-secondary); margin: 16px 0; font-size: 0.875rem; }
    .search-bar { margin-bottom: 16px; text-align: left; }
    .search-bar input[type="text"] {
      width: 100%;
      padding: 10px 14px;
      border: 1px solid var(--border);
      border-radius: 8px;
      font-size: 0.875rem;
      background: var(--card-bg);
      color: var(--text);
      outline: none;
    }
    .search-bar input[type="text"]:focus { border-color: var(--primary); box-shadow: var(--focus-ring); }
    .export-links { margin-left: auto; font-size: 0.7rem; }
    .export-link { color: var(--text-secondary); text-decoration: none; padding: 0 4px; }
    .export-link:hover { color: var(--primary); text-decoration: underline; }
    .pagination { display: flex; justify-content: center; align-items: center; gap: 16px; margin-top: 16px; font-size: 0.875rem; flex-wrap: wrap; }
    .pagination a { color: var(--primary); text-decoration: none; font-weight: 600; }
    .pagination a:hover { text-decoration: underline; }
    .page-info { color: var(--text-secondary); }
    .page-size-form { display: inline-flex; align-items: center; gap: 4px; }
    .page-size-form select { padding: 4px 8px; border: 1px solid var(--border); border-radius: 6px; font-size: 0.813rem; background: var(--card-bg); color: var(--text); }
    .page-size-btn { padding: 4px 10px; border: 1px solid var(--border); border-radius: 6px; font-size: 0.813rem; background: var(--card-bg); color: var(--text); cursor: pointer; }
    .page-size-btn:hover { background: var(--info-bg); }
    .history-table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.875rem; table-layout: fixed; }
    .history-table th { padding: 8px 12px; border-bottom: 2px solid var(--border); font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-secondary); white-space: nowrap; overflow: hidden; }
    .history-table .col-time { width: 22%; }
    .history-table .col-action { width: 18%; }
    .history-table .col-user { width: 14%; }
    .history-table .col-host { width: 20%; }
    .history-table .col-code { width: 20%; }
    .history-table th a { color: var(--text-secondary); text-decoration: none; font-size: 0.75rem; text-transform: none; }
    .history-table th a:hover { color: var(--text); }
    .sort-arrow { font-size: 0.875rem; }
    .filter-clear { font-size: 0.75rem; color: var(--danger); text-decoration: none; margin-left: 4px; }
    .filter-clear:hover { text-decoration: underline; }
    .filter-label { font-size: 0.688rem; font-weight: 400; text-transform: none; letter-spacing: 0; }
    .history-table td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
    .col-time { white-space: nowrap; }
    .timestamp { display: block; }
    .time-ago { display: block; font-size: 0.75rem; color: var(--text-secondary); }
    .col-host { overflow: hidden; text-overflow: ellipsis; max-width: 200px; }
    .col-code { font-family: monospace; font-size: 0.813rem; color: var(--text-secondary); white-space: nowrap; }
    .col-filter-form { display: inline-flex; align-items: center; gap: 2px; margin: 0; padding: 0; text-transform: none; max-width: 100%; }
    .sort-btn { display: inline-block; padding: 4px 6px; margin-left: 4px; color: var(--border); text-decoration: none; font-size: 0.75rem; text-transform: none; border-radius: 4px; }
    .sort-btn:hover { color: var(--text); background: var(--info-bg); }
    .sort-btn.active { color: var(--primary); }
    .col-filter-select {
      padding: 4px 8px;
      border: 1px solid var(--border);
      border-radius: 6px;
      font-size: 0.75rem;
      font-weight: 400;
      text-transform: none;
      background: var(--card-bg);
      color: var(--text);
      cursor: pointer;
      max-width: 120px;
      width: auto;
      appearance: none;
      -webkit-appearance: none;
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath d='M3 5l3 3 3-3' fill='none' stroke='%236b7280' stroke-width='1.5'/%3E%3C/svg%3E");
      background-repeat: no-repeat;
      background-position: right 6px center;
      padding-right: 22px;
    }
    .col-filter-select:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(59,130,246,0.2);
    }
    .filter-toolbar { display: none; }
    .timeline { margin: 16px 0 8px; }
    .timeline-bars { display: flex; align-items: flex-end; gap: 2px; height: 44px; }
    .timeline-bar { flex: 1; background: var(--primary); border-radius: 2px 2px 0 0; min-height: 2px; opacity: 0.5; transition: opacity 0.15s, transform 0.15s; cursor: pointer; text-decoration: none; display: block; }
    .timeline-bar:hover { opacity: 1; transform: scaleY(1.1); transform-origin: bottom; }
    .timeline-bar.now { background: var(--success); opacity: 0.8; }
    .timeline-bar.timeline-active { opacity: 1; outline: 2px solid var(--primary); outline-offset: 1px; }
    .timeline-bar.timeline-active.now { outline-color: var(--success); }
    .timeline-label { font-size: 0.7rem; color: var(--text-secondary); margin-top: 4px; text-align: right; }
    .time-filter-banner { display: flex; align-items: center; gap: 8px; padding: 8px 12px; border-radius: 6px; background: var(--info-bg); border: 1px solid var(--border); margin-bottom: 12px; font-size: 0.813rem; color: var(--text-secondary); }
    .time-filter-clear { color: var(--danger); text-decoration: none; font-weight: 600; margin-left: auto; font-size: 0.75rem; }
    .time-filter-clear:hover { text-decoration: underline; }
    @media (max-width: 600px) {
      .history-table, .history-table thead, .history-table tbody, .history-table th, .history-table td, .history-table tr {
        display: block;
      }
      .history-table thead { display: none; }
      .history-table tr { padding: 12px 0; border-bottom: 1px solid var(--border); }
      .history-table td { padding: 2px 0; border: none; white-space: normal; }
      .history-table td:before { content: attr(data-label); font-weight: 600; font-size: 0.75rem; color: var(--text-secondary); display: block; }
      .filter-toolbar { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }
      .filter-toolbar .col-filter-select { flex: 1; min-width: 0; max-width: none; }
    }
  </style>
  <script nonce="{{.CSPNonce}}">
  if(!document.cookie.split(';').some(function(c){return c.trim().indexOf('pam_tz=')===0;})){
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    if(tz){var d=new Date();d.setTime(d.getTime()+86400000);document.cookie='pam_tz='+tz+';path=/;expires='+d.toUTCString()+';SameSite=Lax';}
  }
  document.addEventListener('DOMContentLoaded',function(){
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    document.querySelectorAll('.col-filter-select,.page-size-select,.tz-select,.lang-select').forEach(function(el){el.addEventListener('change',function(){this.form.submit();});});
    // Select the detected TZ in all tz-select dropdowns
    document.querySelectorAll('.tz-select').forEach(function(sel){
      for(var i=0;i<sel.options.length;i++){if(sel.options[i].value===tz){sel.selectedIndex=i;break;}}
    });
    // Live search: filter table rows as user types
    var searchInput=document.querySelector('.search-bar input[name="q"]');
    if(searchInput){
      searchInput.addEventListener('input',function(){
        var q=this.value.toLowerCase();
        document.querySelectorAll('.history-table tbody tr').forEach(function(row){
          var text=row.textContent.toLowerCase();
          row.style.display=text.indexOf(q)!==-1?'':'none';
        });
      });
    }
    // Profile dropdown toggle
    document.querySelectorAll('.profile-btn').forEach(function(btn){
      btn.addEventListener('click',function(e){
        var menu=btn.closest('.profile-menu');
        var dropdown=menu.querySelector('.profile-dropdown');
        var expanded=dropdown.style.display==='block';
        dropdown.style.display=expanded?'none':'block';
        btn.setAttribute('aria-expanded',!expanded);
        e.stopPropagation();
      });
    });
    document.addEventListener('click',function(){
      document.querySelectorAll('.profile-dropdown').forEach(function(d){d.style.display='none';});
      document.querySelectorAll('.profile-btn').forEach(function(b){b.setAttribute('aria-expanded','false');});
    });
  });
  </script>
</head>
<body class="wide">
  <div class="card">
    <h2>{{call .T "app_name"}}</h2>

    <nav class="nav">
      <a href="/" class="{{if eq .ActivePage "access"}}active{{end}}">{{call .T "access"}}</a>
      <a href="/history" class="{{if eq .ActivePage "history"}}active{{end}}">{{call .T "history"}}</a>
      {{if .IsAdmin}}<a href="/admin" class="{{if eq .ActivePage "admin"}}active{{end}}">{{call .T "admin"}}</a>{{end}}
      <div class="profile-menu" tabindex="-1">
        <button class="profile-btn" type="button" aria-label="{{call .T "aria_user_menu"}}" aria-expanded="false" aria-haspopup="true">{{if .Avatar}}<img src="{{.Avatar}}" class="profile-img" alt="">{{else}}{{.Initial}}{{end}}</button>
        <div class="profile-dropdown">
          <div class="profile-dropdown-label">{{.Username}}{{if .IsAdmin}} <span class="admin-pill">{{call .T "admin"}}</span>{{end}}</div>
          <div class="profile-dropdown-divider"></div>
          <div class="profile-dropdown-label">{{call .T "language"}}</div>
          <form method="GET" action="/history">
            <select name="lang" class="lang-select" aria-label="{{call .T "language"}}">
              {{range .Languages}}<option value="{{.Code}}" {{if eq .Code $.Lang}}selected{{end}}>{{.Name}}</option>{{end}}
            </select>
          </form>
          <div class="profile-dropdown-divider"></div>
          <div class="profile-dropdown-label">{{call .T "timezone"}}</div>
          <form method="GET" action="/history">
            <select name="tz" class="tz-select" aria-label="{{call .T "timezone"}}">` + tzOptionsHTML + `
            </select>
          </form>
          <div class="profile-dropdown-divider"></div>
          <div class="profile-dropdown-label">{{call .T "theme"}}</div>
          <div class="theme-options">
            <a href="/theme?set=system&from=/history" class="theme-option{{if eq .Theme ""}} active{{end}}">{{call .T "theme_system"}}</a>
            <a href="/theme?set=dark&from=/history" class="theme-option{{if eq .Theme "dark"}} active{{end}}">{{call .T "theme_dark"}}</a>
            <a href="/theme?set=light&from=/history" class="theme-option{{if eq .Theme "light"}} active{{end}}">{{call .T "theme_light"}}</a>
          </div>
          <div class="profile-dropdown-divider"></div>
          <a href="/signout" class="profile-dropdown-item" style="color:var(--danger)">{{call .T "sign_out"}}</a>
        </div>
      </div>
    </nav>


    {{if .Timeline}}
    <div class="timeline">
      <div class="timeline-bars">
        {{range .Timeline}}<a href="/history?hours_ago={{.HoursAgo}}&per_page={{$.PerPage}}&user={{$.UserFilter}}" class="timeline-bar{{if .IsNow}} now{{end}}{{if eqInt .HoursAgo $.ActiveHoursAgo}} timeline-active{{end}}" style="height:{{.Height}}px" title="{{.Details}}" aria-label="{{.Details}}"></a>{{end}}
      </div>
      <div class="timeline-label">24h</div>
    </div>
    {{end}}

    {{if .HoursAgo}}
    <div class="time-filter-banner">
      <span>{{call .T "filtered_to_one_hour"}}</span>
      <a href="/history?q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&sort={{.Sort}}&order={{.Order}}&per_page={{.PerPage}}" class="time-filter-clear">{{call .T "clear_time_filter"}}</a>
    </div>
    {{end}}

    <form method="GET" action="/history" class="search-bar">
      <input type="hidden" name="action" value="{{.ActionFilter}}">
      <input type="hidden" name="hostname" value="{{.HostFilter}}">
      {{if .IsAdmin}}<input type="hidden" name="user" value="{{.UserFilter}}">{{end}}
      <input type="hidden" name="sort" value="{{.Sort}}">
      <input type="hidden" name="order" value="{{.Order}}">
      <input type="hidden" name="per_page" value="{{.PerPage}}">
      {{if .HoursAgo}}<input type="hidden" name="hours_ago" value="{{.HoursAgo}}">{{end}}
      <input type="text" name="q" value="{{.Query}}" placeholder="{{call .T "search"}}" aria-label="{{call .T "search"}}">
    </form>

    <div class="filter-toolbar">
      <form method="GET" action="/history" class="filter-form">
        <input type="hidden" name="q" value="{{.Query}}">
        <input type="hidden" name="sort" value="{{.Sort}}">
        <input type="hidden" name="order" value="{{.Order}}">
        <input type="hidden" name="per_page" value="{{.PerPage}}">
        {{if .HoursAgo}}<input type="hidden" name="hours_ago" value="{{.HoursAgo}}">{{end}}
        <select name="action" class="col-filter-select" aria-label="{{call .T "aria_filter_action"}}">
          <option value="">{{call .T "action_all"}}</option>
          {{range .ActionOptions}}<option value="{{.Value}}" {{if eq .Value $.ActionFilter}}selected{{end}}>{{.Label}}</option>{{end}}
        </select>
        <select name="hostname" class="col-filter-select" aria-label="{{call .T "aria_filter_hostname"}}">
          <option value="">{{call .T "host_all"}}</option>
          {{range .HostOptions}}<option value="{{.}}" {{if eq . $.HostFilter}}selected{{end}}>{{.}}</option>{{end}}
        </select>
        {{if .IsAdmin}}<select name="user" class="col-filter-select" aria-label="{{call .T "aria_filter_user"}}">
          <option value="">{{call .T "user_all"}}</option>
          {{range .UserOptions}}<option value="{{.}}" {{if eq . $.UserFilter}}selected{{end}}>{{.}}</option>{{end}}
        </select>{{end}}
      </form>
    </div>

    {{if .History}}
    <table class="history-table">
      <thead>
        <tr>
          <th scope="col" class="col-time">{{call .T "time"}} <a href="/history?sort=timestamp&order={{if eq .Sort "timestamp"}}{{if eq .Order "desc"}}asc{{else}}desc{{end}}{{else}}desc{{end}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&per_page={{.PerPage}}" class="sort-btn{{if eq .Sort "timestamp"}} active{{end}}" title="{{call .T "sort_by_time"}}">{{if and (eq .Sort "timestamp") (eq .Order "asc")}}&#x25b2;{{else}}&#x25bc;{{end}}</a></th>
          <th scope="col" class="col-action"><form method="GET" action="/history" class="col-filter-form">
  <input type="hidden" name="hostname" value="{{.HostFilter}}">
  <input type="hidden" name="user" value="{{.UserFilter}}">
  <input type="hidden" name="q" value="{{.Query}}">
  <input type="hidden" name="sort" value="{{.Sort}}">
  <input type="hidden" name="order" value="{{.Order}}">
  <input type="hidden" name="per_page" value="{{.PerPage}}">
  <select name="action" class="col-filter-select" aria-label="{{call .T "aria_filter_action"}}">
    <option value="">{{call .T "action_all"}}</option>
    {{range .ActionOptions}}<option value="{{.Value}}" {{if eq .Value $.ActionFilter}}selected{{end}}>{{.Label}}</option>{{end}}
  </select>
</form><a href="/history?sort=action&order={{if eq .Sort "action"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}asc{{end}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&per_page={{.PerPage}}" class="sort-btn{{if eq .Sort "action"}} active{{end}}" title="{{call .T "sort_by_action"}}">{{if and (eq .Sort "action") (eq .Order "asc")}}&#x25b2;{{else}}&#x25bc;{{end}}</a></th>
          {{if $.IsAdmin}}<th scope="col" class="col-user"><form method="GET" action="/history" class="col-filter-form">
  <input type="hidden" name="action" value="{{.ActionFilter}}">
  <input type="hidden" name="hostname" value="{{.HostFilter}}">
  <input type="hidden" name="q" value="{{.Query}}">
  <input type="hidden" name="sort" value="{{.Sort}}">
  <input type="hidden" name="order" value="{{.Order}}">
  <input type="hidden" name="per_page" value="{{.PerPage}}">
  <select name="user" class="col-filter-select" aria-label="{{call .T "aria_filter_user"}}">
    <option value="">{{call .T "user_all"}}</option>
    {{range .UserOptions}}<option value="{{.}}" {{if eq . $.UserFilter}}selected{{end}}>{{.}}</option>{{end}}
  </select>
</form><a href="/history?sort=user&order={{if eq .Sort "user"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}asc{{end}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&per_page={{.PerPage}}" class="sort-btn{{if eq .Sort "user"}} active{{end}}">{{if and (eq .Sort "user") (eq .Order "asc")}}&#x25b2;{{else}}&#x25bc;{{end}}</a></th>{{end}}
          <th scope="col" class="col-host"><form method="GET" action="/history" class="col-filter-form">
  <input type="hidden" name="action" value="{{.ActionFilter}}">
  <input type="hidden" name="user" value="{{.UserFilter}}">
  <input type="hidden" name="q" value="{{.Query}}">
  <input type="hidden" name="sort" value="{{.Sort}}">
  <input type="hidden" name="order" value="{{.Order}}">
  <input type="hidden" name="per_page" value="{{.PerPage}}">
  <select name="hostname" class="col-filter-select" aria-label="{{call .T "aria_filter_hostname"}}">
    <option value="">{{call .T "host_all"}}</option>
    {{range .HostOptions}}<option value="{{.}}" {{if eq . $.HostFilter}}selected{{end}}>{{.}}</option>{{end}}
  </select>
</form><a href="/history?sort=hostname&order={{if eq .Sort "hostname"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}asc{{end}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&per_page={{.PerPage}}" class="sort-btn{{if eq .Sort "hostname"}} active{{end}}" title="{{call .T "sort_by_host"}}">{{if and (eq .Sort "hostname") (eq .Order "asc")}}&#x25b2;{{else}}&#x25bc;{{end}}</a></th>
          <th scope="col" class="col-code">{{call .T "code"}} <a href="/history?sort=code&order={{if eq .Sort "code"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}asc{{end}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&per_page={{.PerPage}}" class="sort-btn{{if eq .Sort "code"}} active{{end}}" title="{{call .T "sort_by_code"}}">{{if and (eq .Sort "code") (eq .Order "asc")}}&#x25b2;{{else}}&#x25bc;{{end}}</a></th>
        </tr>
      </thead>
      <tbody>
        {{range .History}}
        <tr>
          <td data-label="{{call $.T "time"}}" class="col-time">
            <span class="timestamp">{{.FormattedTime}}</span>
            <span class="time-ago">({{.TimeAgo}})</span>
          </td>
          <td data-label="{{call $.T "action"}}" class="col-action"><span class="history-action {{.Action}}">{{.ActionLabel}}</span>{{if .Actor}} <span class="history-actor">{{call $.T "by"}} {{.Actor}}</span>{{end}}</td>
          {{if $.IsAdmin}}<td data-label="{{call $.T "user"}}">{{.Username}}</td>{{end}}
          <td data-label="{{call $.T "host"}}" class="col-host">{{.Hostname}}</td>
          <td data-label="{{call $.T "code"}}" class="col-code">{{if .Code}}{{.Code}}{{end}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
    <div class="pagination">
      {{if .HasPrev}}<a href="/history?page={{sub .Page 1}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&sort={{.Sort}}&order={{.Order}}&per_page={{.PerPage}}">&#8592; {{call .T "previous"}}</a>{{end}}
      <span class="page-info">{{call .T "page"}} {{.Page}} {{call .T "of"}} {{.TotalPages}}</span>
      {{if .HasNext}}<a href="/history?page={{add .Page 1}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&sort={{.Sort}}&order={{.Order}}&per_page={{.PerPage}}">{{call .T "next"}} &#8594;</a>{{end}}
      <form method="GET" action="/history" class="page-size-form">
        <input type="hidden" name="action" value="{{.ActionFilter}}">
        <input type="hidden" name="hostname" value="{{.HostFilter}}">
        <input type="hidden" name="user" value="{{.UserFilter}}">
        <input type="hidden" name="sort" value="{{.Sort}}">
        <input type="hidden" name="order" value="{{.Order}}">
        <input type="hidden" name="q" value="{{.Query}}">
        <select name="per_page" class="page-size-select" aria-label="{{call .T "aria_page_size"}}">
          {{range .PerPageOptions}}<option value="{{.}}" {{if eqInt . $.PerPage}}selected{{end}}>{{.}}</option>{{end}}
        </select>
        <button type="submit" class="page-size-btn">{{call .T "go"}}</button>
      </form>
      <span class="export-links"><a href="/api/history/export?format=csv" class="export-link">{{call .T "export_csv"}}</a> <a href="/api/history/export?format=json" class="export-link">{{call .T "export_json"}}</a></span>
    </div>
    {{else}}
    <p class="empty-state">{{call .T "no_activity"}}</p>
    {{end}}
  </div>
</body>
</html>`



const adminPageHTML = `<!DOCTYPE html>
<html lang="{{.Lang}}" class="{{if eq .Theme "dark"}}theme-dark{{else if eq .Theme "light"}}theme-light{{end}}">
<head>
  <title>{{call .T "admin"}} - {{call .T "app_name"}}</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="240">
  <style>` + sharedCSS + navCSS + `
    body { align-items: flex-start; padding-top: 32px; }
    .admin-tabs { display: flex; gap: 4px; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); justify-content: center; flex-wrap: wrap; }
    .admin-tabs a { padding: 6px 12px; border-radius: 6px; font-size: 0.8rem; color: var(--text-secondary); text-decoration: none; }
    .admin-tabs a:hover { background: var(--info-bg); color: var(--text); }
    .admin-tabs a.active { background: var(--primary); color: var(--primary-text); font-weight: 600; }
    .info-section { margin-bottom: 24px; }
    .info-section h3 { font-size: 0.875rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-secondary); margin-bottom: 12px; }
    .info-table { width: 100%; border-collapse: collapse; }
    .info-table td { padding: 8px 12px; border-bottom: 1px solid var(--border); font-size: 0.875rem; }
    .info-label { color: var(--text-secondary); width: 40%; }
    .section-label { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-secondary); margin: 24px 0 8px; text-align: left; }
    .list { text-align: left; margin: 0 0 8px; }
    .row { display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid var(--border); gap: 12px; }
    .row-info { min-width: 0; flex: 1; }
    .row-host { font-weight: 600; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .row-sub { color: var(--text-secondary); font-size: 0.813rem; display: block; }
    .row-active { color: var(--success); font-size: 0.813rem; font-weight: 600; display: block; }
    .banner { padding: 10px 16px; border-radius: 8px; margin-bottom: 12px; font-size: 0.875rem; font-weight: 600; text-align: left; }
    .banner-success { background: var(--success-bg); border: 1px solid var(--success-border); color: var(--success); }
    .host-btn { display: inline-block; padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 0.75rem; font-weight: 600; white-space: nowrap; border: 1px solid var(--border); background: none; color: var(--text-secondary); text-decoration: none; text-align: center; line-height: 1.4; }
    .host-btn:hover { background: var(--info-bg); color: var(--text); }
    .host-btn.danger { border-color: var(--danger); color: var(--danger); }
    .host-btn.danger:hover { background: var(--danger-bg); }
    .host-btn.primary { border-color: var(--primary); color: var(--primary); }
    .host-btn.primary:hover { background: var(--info-bg); }
    .host-btn.filled { background: var(--primary); border-color: var(--primary); color: var(--primary-text); }
    .host-btn.filled:hover { background: var(--primary-hover); }
    .bulk-actions { margin: 16px 0 8px; text-align: right; }
    .bulk-btn { background: none; border: 1px solid var(--border); color: var(--text-secondary); padding: 6px 16px; border-radius: 6px; cursor: pointer; font-size: 0.75rem; font-weight: 600; }
    .bulk-btn:hover { background: var(--info-bg); color: var(--text); }
    .bulk-btn.primary { border-color: var(--primary); color: var(--primary); }
    .bulk-btn.primary:hover { background: var(--info-bg); }
    .bulk-btn.danger { border-color: var(--danger-border); color: var(--danger); }
    .bulk-btn.danger:hover { background: var(--danger-bg); }
    .host-group { font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; background: var(--info-bg); color: var(--text-secondary); margin-left: 8px; vertical-align: middle; }
    .hosts-toolbar { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
    .modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,.5); z-index: 1000; overflow-y: auto; }
    .modal-overlay.open { display: flex; align-items: flex-start; justify-content: center; padding: 40px 16px; }
    .modal-box { background: var(--card-bg); border: 1px solid var(--border); border-radius: 16px; padding: 24px; width: 100%; max-width: 520px; }
    .modal-box h3 { margin: 0 0 16px; font-size: 1rem; }
    .modal-field { margin-bottom: 12px; }
    .modal-field label { display: block; font-size: 0.813rem; font-weight: 600; margin-bottom: 4px; }
    .modal-field input,.modal-field select { width: 100%; box-sizing: border-box; padding: 8px 10px; border: 1px solid var(--border); border-radius: 8px; background: var(--card-bg); color: var(--text); font-size: 0.875rem; font-family: inherit; }
    .modal-field input:focus,.modal-field select:focus { outline: none; border-color: var(--primary); box-shadow: var(--focus-ring); }
    .modal-field select { appearance: none; -webkit-appearance: none; background-image: url("data:image/svg+xml;charset=utf-8,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%23888' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 10px center; background-size: 12px; padding-right: 30px; cursor: pointer; }
    .modal-row { display: flex; gap: 8px; }
    .modal-row .modal-field { flex: 1; }
    .modal-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }
    .modal-actions .host-btn { min-width: 90px; justify-content: center; }
    .host-btn:disabled { opacity: 0.38; cursor: not-allowed; }
    .key-upload-row { display: flex; gap: 8px; }
    .key-action-btn { display: flex; align-items: center; justify-content: center; gap: 6px; flex: 1; padding: 9px 14px; border: 1px solid var(--border); border-radius: 8px; background: var(--bg); color: var(--text); font-size: 0.813rem; font-weight: 600; font-family: inherit; cursor: pointer; text-align: center; }
    .key-action-btn:hover { border-color: var(--primary); color: var(--primary); }
    .key-info-card { display: flex; align-items: center; gap: 10px; padding: 10px 12px; border: 1px solid var(--success); border-radius: 8px; background: var(--success-bg, rgba(34,197,94,.08)); margin-bottom: 8px; }
    .key-info-icon { color: var(--success); font-size: 1rem; flex-shrink: 0; }
    .key-info-text { min-width: 0; }
    .key-info-type { font-size: 0.75rem; font-weight: 700; color: var(--success); text-transform: uppercase; letter-spacing: .05em; }
    .key-info-fp { font-size: 0.75rem; font-family: monospace; color: var(--text-secondary); word-break: break-all; }
    .key-clear-btn { font-size: 0.75rem; color: var(--text-secondary); background: none; border: none; cursor: pointer; padding: 0; text-decoration: underline; }
    .key-clear-btn:hover { color: var(--text); }
    .deploy-log { background: var(--terminal-bg); color: var(--terminal-text); font-family: monospace; font-size: 0.75rem; border-radius: 8px; padding: 12px; max-height: 300px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; margin-top: 12px; display: none; }
    .deploy-log.visible { display: block; }
    .deploy-status { font-size: 0.813rem; font-weight: 600; margin-top: 8px; }
    .deploy-status.ok { color: var(--success); }
    .deploy-status.err { color: var(--danger); }
    .group-filter { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; font-size: 0.813rem; }
    .group-filter select { padding: 6px 10px; border: 1px solid var(--border); border-radius: 8px; background: var(--card-bg); color: var(--text); font-size: 0.813rem; cursor: pointer; }
    .elevate-form { display: flex; gap: 8px; align-items: center; flex-shrink: 0; }
    .session-row { display: flex; justify-content: space-between; align-items: center; padding: 2px 0; }
    .session-actions { display: flex; gap: 4px; flex-shrink: 0; }
    .host-row-header { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
    .host-row-header-info { min-width: 0; flex: 1; display: flex; align-items: center; flex-wrap: wrap; gap: 6px; }
    .host-row-header-actions { display: flex; gap: 4px; flex-shrink: 0; align-items: center; }
    .host-row-users { margin-top: 4px; margin-left: 12px; border-left: 2px solid var(--border); padding-left: 8px; }
    .seg-btn { display: inline-flex; border-radius: 6px; overflow: hidden; border: 1px solid var(--primary); flex-shrink: 0; }
    .seg-btn button { background: none; border: none; border-right: 1px solid var(--primary); padding: 6px 9px; cursor: pointer; color: var(--primary); font-size: 0.75rem; font-weight: 600; font-family: inherit; line-height: 1.4; }
    .seg-btn button:last-child { border-right: none; }
    .seg-btn button:hover { background: var(--primary); color: var(--bg); }
    .empty-state { color: var(--text-secondary); margin: 16px 0; font-size: 0.875rem; }
    .history-action { font-weight: 600; }
    .history-action.approved { color: var(--success); }
    .history-action.revoked { color: var(--danger); }
    .history-action.auto_approved { color: var(--primary); }
    .history-action.rejected { color: var(--danger); }
    .history-action.elevated { color: var(--primary); }
    .history-action.extended { color: var(--primary); }
    .history-action.rotated_breakglass { color: var(--text-secondary); }
    .history-actor { font-size: 0.7rem; color: var(--text-secondary); font-weight: 400; }
    .search-bar { margin-bottom: 16px; text-align: left; }
    .search-bar input[type="text"] { width: 100%; padding: 10px 14px; border: 1px solid var(--border); border-radius: 8px; font-size: 0.875rem; background: var(--card-bg); color: var(--text); outline: none; }
    .search-bar input[type="text"]:focus { border-color: var(--primary); box-shadow: var(--focus-ring); }
    .pagination { display: flex; justify-content: center; align-items: center; gap: 16px; margin-top: 16px; font-size: 0.875rem; flex-wrap: wrap; }
    .pagination a { color: var(--primary); text-decoration: none; font-weight: 600; }
    .pagination a:hover { text-decoration: underline; }
    .page-info { color: var(--text-secondary); }
    .page-size-form { display: inline-flex; align-items: center; gap: 4px; }
    .page-size-form select { padding: 4px 8px; border: 1px solid var(--border); border-radius: 6px; font-size: 0.813rem; background: var(--card-bg); color: var(--text); }
    .page-size-btn { padding: 4px 10px; border: 1px solid var(--border); border-radius: 6px; font-size: 0.813rem; background: var(--card-bg); color: var(--text); cursor: pointer; }
    .page-size-btn:hover { background: var(--info-bg); }
    .history-table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.875rem; table-layout: fixed; }
    .history-table th { padding: 8px 12px; border-bottom: 2px solid var(--border); font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-secondary); white-space: nowrap; overflow: hidden; }
    .history-table .col-time { width: 22%; }
    .history-table .col-action { width: 18%; }
    .history-table .col-user { width: 14%; }
    .history-table .col-host { width: 20%; }
    .history-table .col-code { width: 20%; }
    .history-table th a { color: var(--text-secondary); text-decoration: none; font-size: 0.75rem; text-transform: none; }
    .history-table th a:hover { color: var(--text); }
    .history-table td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
    .col-time { white-space: nowrap; }
    .timestamp { display: block; }
    .time-ago { display: block; font-size: 0.75rem; color: var(--text-secondary); }
    .col-host { overflow: hidden; text-overflow: ellipsis; max-width: 200px; }
    .col-code { font-family: monospace; font-size: 0.813rem; color: var(--text-secondary); white-space: nowrap; }
    .col-filter-form { display: inline-flex; align-items: center; gap: 2px; margin: 0; padding: 0; text-transform: none; max-width: 100%; }
    .col-filter-select { padding: 4px 8px; border: 1px solid var(--border); border-radius: 6px; font-size: 0.75rem; background: var(--card-bg); color: var(--text); cursor: pointer; appearance: none; -webkit-appearance: none; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath d='M3 5l3 3 3-3' fill='none' stroke='%236b7280' stroke-width='1.5'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 6px center; padding-right: 22px; max-width: 120px; width: auto; }
    .col-filter-select:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 2px rgba(59,130,246,0.2); }
    .sort-btn { display: inline-block; padding: 4px 6px; margin-left: 4px; color: var(--border); text-decoration: none; font-size: 0.75rem; border-radius: 4px; }
    .sort-btn:hover { color: var(--text); background: var(--info-bg); }
    .sort-btn.active { color: var(--primary); }
    .user-name { font-weight: 600; }
    .group-badge { display: inline-block; font-size: 0.65rem; padding: 1px 6px; border-radius: 8px; background: var(--info-bg); color: var(--text-secondary); white-space: nowrap; margin-right: 3px; margin-bottom: 2px; text-decoration: none; }
    .group-badge-link:hover { background: var(--primary); color: var(--primary-text); }
    .summary-chip { font-size: 0.65rem; padding: 2px 8px; border-radius: 8px; cursor: pointer; white-space: nowrap; user-select: none; display: inline-flex; align-items: center; gap: 4px; transition: opacity 0.15s; }
    .summary-chip:hover { opacity: 0.8; }
    .summary-chip.commands { background: var(--chip-cmd-bg); color: var(--primary); border: 1px solid var(--chip-cmd-border); }
    .summary-chip.hosts { background: var(--chip-host-bg); color: var(--success); border: 1px solid var(--chip-host-border); }
    .summary-chip.all { background: var(--chip-all-bg); color: var(--chip-all-text); border: 1px solid var(--chip-all-border); cursor: default; }
    .summary-chip.single { background: var(--info-bg); color: var(--text-secondary); border: 1px solid var(--border); cursor: default; font-family: monospace; }
    .summary-sep { font-size: 0.65rem; color: var(--text-secondary); }
    .caret { font-size: 0.55rem; transition: transform 0.2s; display: inline-block; }
    .summary-chip.open .caret { transform: rotate(180deg); }
    .expanded-list { display: none; margin-top: 6px; }
    .expanded-list.visible { display: flex; flex-wrap: wrap; gap: 3px; max-width: 300px; }
    .pill { display: inline-block; font-size: 0.65rem; padding: 1px 6px; border-radius: 4px; white-space: nowrap; }
    .pill.cmd { background: rgba(59,130,246,0.1); color: #93c5fd; font-family: monospace; }
    .pill.host { background: rgba(16,185,129,0.1); color: #6ee7b7; }
    .user-card-meta { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; font-size: 0.78rem; color: var(--text-secondary); padding: 4px 0 2px; }
    .user-card-actions { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 6px; }
    .group-card-row { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; font-size: 0.8rem; padding: 2px 0; }
    .group-card-label { font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-secondary); white-space: nowrap; }
  </style>
  <script nonce="{{.CSPNonce}}">
  if(!document.cookie.split(';').some(function(c){return c.trim().indexOf('pam_tz=')===0;})){
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    if(tz){var d=new Date();d.setTime(d.getTime()+86400000);document.cookie='pam_tz='+tz+';path=/;expires='+d.toUTCString()+';SameSite=Lax';}
  }
  var _t={copied:'{{call .T "copied"}}',deployOk:'{{call .T "deploy_success"}}',deployFailed:'{{call .T "deploy_failed"}}',requestFailed:'{{call .T "request_failed"}}',clipboardEmpty:'{{call .T "clipboard_empty"}}',clipboardError:'{{call .T "clipboard_error"}}',loadingUsers:'{{call .T "deploy_user_loading"}}',unavailable:'{{call .T "deploy_user_unavailable"}}',deployRun:'{{call .T "deploy_run"}}',starting:'{{call .T "deploy_starting"}}',hostRequired:'{{call .T "host_required"}}',keyRequired:'{{call .T "key_required"}}',connLost:'{{call .T "connection_lost"}}',deployForbidden:'{{call .T "deploy_forbidden"}}'};
  document.addEventListener('DOMContentLoaded',function(){
    // Auto-dismiss success banners after 5 seconds
    document.querySelectorAll('.banner-success').forEach(function(el){
      setTimeout(function(){el.style.transition='opacity 0.4s';el.style.opacity='0';setTimeout(function(){el.style.display='none';},400);},5000);
    });
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    document.querySelectorAll('.col-filter-select,.page-size-select,.tz-select,.lang-select').forEach(function(el){el.addEventListener('change',function(){this.form.submit();});});
    document.querySelectorAll('.tz-select').forEach(function(sel){
      for(var i=0;i<sel.options.length;i++){if(sel.options[i].value===tz){sel.selectedIndex=i;break;}}
    });
    var searchInput=document.querySelector('.search-bar input[name="q"]');
    if(searchInput){
      searchInput.addEventListener('input',function(){
        var q=this.value.toLowerCase();
        document.querySelectorAll('.history-table tbody tr,.users-table tbody tr').forEach(function(row){
          var text=row.textContent.toLowerCase();
          row.style.display=text.indexOf(q)!==-1?'':'none';
        });
      });
    }
    // Profile dropdown toggle
    document.querySelectorAll('.profile-btn').forEach(function(btn){
      btn.addEventListener('click',function(e){
        var menu=btn.closest('.profile-menu');
        var dropdown=menu.querySelector('.profile-dropdown');
        var expanded=dropdown.style.display==='block';
        dropdown.style.display=expanded?'none':'block';
        btn.setAttribute('aria-expanded',!expanded);
        e.stopPropagation();
      });
    });
    document.addEventListener('click',function(){
      document.querySelectorAll('.profile-dropdown').forEach(function(d){d.style.display='none';});
      document.querySelectorAll('.profile-btn').forEach(function(b){b.setAttribute('aria-expanded','false');});
    });
    var installBtn=document.getElementById('install-copy-btn');
    if(installBtn){
      installBtn.addEventListener('click',function(){
        var cmd=installBtn.getAttribute('data-cmd');
        var orig=installBtn.innerHTML;
        navigator.clipboard.writeText(cmd).then(function(){
          installBtn.innerHTML='&#10003; '+_t.copied;
          setTimeout(function(){installBtn.innerHTML=orig;},2000);
        }).catch(function(){
          var ta=document.createElement('textarea');
          ta.value=cmd;ta.style.position='fixed';ta.style.opacity='0';
          document.body.appendChild(ta);ta.select();
          try{document.execCommand('copy');installBtn.innerHTML='&#10003; '+_t.copied;}catch(e){}
          document.body.removeChild(ta);
          setTimeout(function(){installBtn.innerHTML=orig;},2000);
        });
      });
    }
    // Deploy modal
    var deployOpenBtn=document.getElementById('deploy-open-btn');
    var deployModal=document.getElementById('deploy-modal');
    var deployCancelBtn=document.getElementById('deploy-cancel-btn');
    var deploySubmitBtn=document.getElementById('deploy-submit-btn');
    var deployCloseBtn=document.getElementById('deploy-close-btn');
    var deployPrivKey=''; // in-memory only, never written to DOM

    function deployCheckReady(){
      var host=document.getElementById('deploy-host').value.trim();
      if(deploySubmitBtn) deploySubmitBtn.disabled=!(host && deployPrivKey);
    }

    function deployResetKey(){
      deployPrivKey='';
      document.getElementById('deploy-key-empty').style.display='';
      document.getElementById('deploy-key-loaded').style.display='none';
      document.getElementById('deploy-key-validating').style.display='none';
      document.getElementById('deploy-key-invalid').style.display='none';
      document.getElementById('deploy-key-file').value='';
      deployCheckReady();
    }

    function deployValidateKey(pem){
      document.getElementById('deploy-key-validating').style.display='';
      document.getElementById('deploy-key-invalid').style.display='none';
      fetch('/api/deploy/pubkey',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({private_key:pem})})
      .then(function(r){
        if(!r.ok){return r.text().then(function(t){throw new Error(t||r.statusText);});}
        return r.json();
      })
      .then(function(d){
        deployPrivKey=pem;
        document.getElementById('deploy-key-validating').style.display='none';
        document.getElementById('deploy-key-empty').style.display='none';
        document.getElementById('deploy-key-type').textContent=d.type;
        document.getElementById('deploy-key-fp').textContent=d.fingerprint;
        document.getElementById('deploy-key-loaded').style.display='';
        deployCheckReady();
      })
      .catch(function(err){
        deployPrivKey='';
        document.getElementById('deploy-key-validating').style.display='none';
        var inv=document.getElementById('deploy-key-invalid');
        inv.textContent=err.message||'Invalid key';
        inv.style.display='';
        if(deploySubmitBtn) deploySubmitBtn.disabled=true;
      });
    }

    var _deployPrevFocus=null;
    function openDeployModal(){
      _deployPrevFocus=document.activeElement;
      deployModal.classList.add('open');
      document.getElementById('deploy-form-area').style.display='';
      document.getElementById('deploy-log-area').style.display='none';
      document.getElementById('deploy-error').style.display='none';
      document.getElementById('deploy-log').textContent='';
      document.getElementById('deploy-status').textContent='';
      document.getElementById('deploy-status').className='deploy-status';
      deployResetKey();
      // Focus first field
      setTimeout(function(){var h=document.getElementById('deploy-host');if(h)h.focus();},50);
      // Load PocketID users with SSH keys
      var sel=document.getElementById('deploy-pocketid-user');
      sel.innerHTML='<option value="">'+_t.loadingUsers+'</option>';
      fetch('/api/deploy/users').then(function(r){return r.json();}).then(function(users){
        sel.innerHTML='<option value="">(none)</option>';
        (users||[]).forEach(function(u){
          var o=document.createElement('option');
          o.value=u.username;
          o.textContent=u.username+(u.email?' \u2014 '+u.email:'');
          sel.appendChild(o);
        });
      }).catch(function(){sel.innerHTML='<option value="">'+_t.unavailable+'</option>';});
    }
    function closeDeployModal(){
      deployModal.classList.remove('open');
      if(_deployPrevFocus)_deployPrevFocus.focus();
    }
    if(deployOpenBtn){
      deployOpenBtn.addEventListener('click',openDeployModal);
      deployCancelBtn.addEventListener('click',closeDeployModal);
      deployCloseBtn.addEventListener('click',closeDeployModal);
      deployModal.addEventListener('click',function(e){if(e.target===deployModal)closeDeployModal();});
      document.addEventListener('keydown',function(e){if(e.key==='Escape'&&deployModal.classList.contains('open'))closeDeployModal();});
      document.getElementById('deploy-host').addEventListener('input',deployCheckReady);
      // Paste key from clipboard
      document.getElementById('deploy-key-paste-btn').addEventListener('click',function(){
        navigator.clipboard.readText().then(function(text){
          if(text.trim()) deployValidateKey(text.trim());
          else{var inv=document.getElementById('deploy-key-invalid');inv.textContent=_t.clipboardEmpty;inv.style.display='';}
        }).catch(function(){
          var inv=document.getElementById('deploy-key-invalid');
          inv.textContent=_t.clipboardError;
          inv.style.display='';
        });
      });
      // Upload key from file
      document.getElementById('deploy-key-file').addEventListener('change',function(){
        var f=this.files[0];
        if(!f) return;
        var reader=new FileReader();
        reader.onload=function(e){deployValidateKey(e.target.result.trim());};
        reader.readAsText(f);
      });
      // Clear key
      document.getElementById('deploy-key-clear-btn').addEventListener('click',deployResetKey);
      // Submit
      deploySubmitBtn.addEventListener('click',function(){
        var host=document.getElementById('deploy-host').value.trim();
        var port=parseInt(document.getElementById('deploy-port').value)||22;
        var sshUser=document.getElementById('deploy-ssh-user').value.trim()||'root';
        var pocketidUser=document.getElementById('deploy-pocketid-user').value;
        var errEl=document.getElementById('deploy-error');
        if(!host){errEl.textContent=_t.hostRequired;errEl.style.display='';return;}
        if(!deployPrivKey){errEl.textContent=_t.keyRequired;errEl.style.display='';return;}
        errEl.style.display='none';
        deploySubmitBtn.disabled=true;
        deploySubmitBtn.textContent=_t.starting;
        fetch('/api/deploy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({hostname:host,port:port,ssh_user:sshUser,private_key:deployPrivKey,pocketid_user:pocketidUser})})
        .then(function(r){
          if(!r.ok){if(r.status===403){throw new Error(_t.deployForbidden);}return r.text().then(function(t){throw new Error(t||r.statusText);});}
          return r.json();
        })
        .then(function(data){
          deployPrivKey=''; // clear key from memory once submitted
          deploySubmitBtn.disabled=false;
          deploySubmitBtn.textContent=_t.deployRun;
          document.getElementById('deploy-form-area').style.display='none';
          document.getElementById('deploy-log-area').style.display='';
          var logEl=document.getElementById('deploy-log');
          var statusEl=document.getElementById('deploy-status');
          var es=new EventSource('/api/deploy/stream/'+data.id);
          es.addEventListener('message',function(e){
            logEl.textContent+=e.data+'\n';
            logEl.scrollTop=logEl.scrollHeight;
          });
          es.addEventListener('status',function(e){
            es.close();
            if(e.data==='done'){statusEl.textContent='\u2713 '+_t.deployOk;statusEl.className='deploy-status ok';}
            else{statusEl.textContent='\u2717 '+_t.deployFailed;statusEl.className='deploy-status err';}
          });
          es.onerror=function(){es.close();if(!statusEl.textContent){statusEl.textContent=_t.connLost;statusEl.className='deploy-status err';}};
        })
        .catch(function(err){
          deploySubmitBtn.disabled=false;
          deploySubmitBtn.textContent=_t.deployRun;
          errEl.textContent=err.message||_t.requestFailed;
          errEl.style.display='';
        });
      });
    }
  });
  document.addEventListener('click',function(e){
    var chip=e.target.closest('.summary-chip.expandable');
    if(!chip)return;
    var cell=chip.closest('.perms-cell');
    var listType=chip.classList.contains('commands')?'cmd':'host';
    var list=cell.querySelector('.expanded-list[data-type="'+listType+'"]');
    var open=list.classList.contains('visible');
    list.classList.toggle('visible',!open);
    chip.classList.toggle('open',!open);
  });
  </script>
</head>
<body class="wide">
  <div class="card">
    <h2>{{call .T "app_name"}}</h2>

    <nav class="nav">
      <a href="/" class="{{if eq .ActivePage "access"}}active{{end}}">{{call .T "access"}}</a>
      <a href="/history" class="{{if eq .ActivePage "history"}}active{{end}}">{{call .T "history"}}</a>
      <a href="/admin" class="{{if eq .ActivePage "admin"}}active{{end}}">{{call .T "admin"}}</a>
      <div class="profile-menu" tabindex="-1">
        <button class="profile-btn" type="button" aria-label="{{call .T "aria_user_menu"}}" aria-expanded="false" aria-haspopup="true">{{if .Avatar}}<img src="{{.Avatar}}" class="profile-img" alt="">{{else}}{{.Initial}}{{end}}</button>
        <div class="profile-dropdown">
          <div class="profile-dropdown-label">{{.Username}} <span class="admin-pill">{{call .T "admin"}}</span></div>
          <div class="profile-dropdown-divider"></div>
          <div class="profile-dropdown-label">{{call .T "language"}}</div>
          <form method="GET" action="/admin/{{.AdminTab}}">
            <select name="lang" class="lang-select" aria-label="{{call .T "language"}}">
              {{range .Languages}}<option value="{{.Code}}" {{if eq .Code $.Lang}}selected{{end}}>{{.Name}}</option>{{end}}
            </select>
          </form>
          <div class="profile-dropdown-divider"></div>
          <div class="profile-dropdown-label">{{call .T "timezone"}}</div>
          <form method="GET" action="/admin/{{.AdminTab}}">
            <select name="tz" class="tz-select" aria-label="{{call .T "timezone"}}">` + tzOptionsHTML + `
            </select>
          </form>
          <div class="profile-dropdown-divider"></div>
          <div class="profile-dropdown-label">{{call .T "theme"}}</div>
          <div class="theme-options">
            <a href="/theme?set=system&from=/admin" class="theme-option{{if eq .Theme ""}} active{{end}}">{{call .T "theme_system"}}</a>
            <a href="/theme?set=dark&from=/admin" class="theme-option{{if eq .Theme "dark"}} active{{end}}">{{call .T "theme_dark"}}</a>
            <a href="/theme?set=light&from=/admin" class="theme-option{{if eq .Theme "light"}} active{{end}}">{{call .T "theme_light"}}</a>
          </div>
          <div class="profile-dropdown-divider"></div>
          <a href="/signout" class="profile-dropdown-item" style="color:var(--danger)">{{call .T "sign_out"}}</a>
        </div>
      </div>
    </nav>

    <div class="admin-tabs">
      <a href="/admin/users" class="{{if eq .AdminTab "users"}}active{{end}}">{{call .T "users"}}</a>
      <a href="/admin/groups" class="{{if eq .AdminTab "groups"}}active{{end}}">{{call .T "groups"}}</a>
      <a href="/admin/hosts" class="{{if eq .AdminTab "hosts"}}active{{end}}">{{call .T "hosts"}}</a>
      <a href="/admin/info" class="{{if eq .AdminTab "info"}}active{{end}}">{{call .T "info"}}</a>
    </div>

    {{range .Flashes}}<div class="banner banner-success" role="alert">{{.}}</div>{{end}}

    {{if eq .AdminTab "info"}}
    <div class="info-section">
      <h3>{{call .T "server_config"}}</h3>
      <table class="info-table">
        <tr><td class="info-label">{{call .T "version"}}</td><td>{{.Version}}{{if .Commit}} <span style="color:var(--text-secondary);font-size:0.85em">({{.Commit}})</span>{{end}}</td></tr>
        <tr><td class="info-label">{{call .T "grace_period"}}</td><td>{{.GracePeriod}}</td></tr>
        <tr><td class="info-label">{{call .T "onetap_max_age"}}</td><td>{{.OneTapMaxAge}}</td></tr>
        <tr><td class="info-label">{{call .T "challenge_ttl"}}</td><td>{{.ChallengeTTL}}</td></tr>
        <tr><td class="info-label">{{call .T "breakglass_type"}}</td><td>{{.BreakglassType}}</td></tr>
        <tr><td class="info-label">{{call .T "breakglass_rotation_days"}}</td><td>{{.BreakglassRotation}}</td></tr>
        <tr><td class="info-label">{{call .T "token_cache"}}</td><td>{{.TokenCache}}</td></tr>
        <tr><td class="info-label">{{call .T "default_page_size"}}</td><td>{{.DefaultPageSize}}</td></tr>
        <tr><td class="info-label">{{call .T "escrow_configured"}}</td><td>{{.EscrowConfigured}}</td></tr>
        <tr><td class="info-label">{{call .T "notifications_configured"}}</td><td>{{.NotifyConfigured}}</td></tr>
        <tr><td class="info-label">{{call .T "host_registry"}}</td><td>{{.HostRegistry}}</td></tr>
        <tr><td class="info-label">{{call .T "session_persistence"}}</td><td>{{.SessionPersistence}}</td></tr>
        <tr><td class="info-label">{{call .T "admin_groups"}}</td><td>{{.AdminGroups}}</td></tr>
        <tr><td class="info-label">{{call .T "admin_approval_hosts"}}</td><td>{{.AdminApprovalHosts}}</td></tr>
      </table>
    </div>
    <div class="info-section">
      <h3>{{call .T "system_info"}}</h3>
      <table class="info-table">
        <tr><td class="info-label">{{call .T "uptime"}}</td><td>{{.Uptime}}</td></tr>
        <tr><td class="info-label">{{call .T "go_version"}}</td><td>{{.GoVersion}}</td></tr>
        <tr><td class="info-label">{{call .T "os_arch"}}</td><td>{{.OSArch}}</td></tr>
        <tr><td class="info-label">{{call .T "goroutines"}}</td><td>{{.Goroutines}}</td></tr>
        <tr><td class="info-label">{{call .T "memory_usage"}}</td><td>{{.MemUsage}}</td></tr>
        <tr><td class="info-label">{{call .T "active_sessions"}}</td><td>{{.ActiveSessionsCount}}</td></tr>
      </table>
    </div>

    {{else if eq .AdminTab "users"}}
    {{if .Users}}
    <div class="list" role="list">
      {{range .Users}}
      <div class="row" role="listitem" style="flex-direction:column;align-items:stretch;gap:0">
        <div class="host-row-header">
          <div class="host-row-header-info">
            <span class="user-name">{{.Username}}</span>
            {{if .Groups}}{{range .Groups}}<a href="/admin/groups#group-{{.Name}}" class="group-badge group-badge-link">{{.Name}}</a>{{end}}{{end}}
          </div>
          <div class="host-row-header-actions">
            {{if gt .ActiveSessions 0}}
            <form method="POST" action="/api/sessions/revoke-all" style="display:inline">
              <input type="hidden" name="username" value="{{$.Username}}">
              <input type="hidden" name="session_username" value="{{.Username}}">
              <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
              <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
              <input type="hidden" name="from" value="/admin/users">
              <button type="submit" class="host-btn danger" onclick="return confirm('{{printf (call $.T "confirm_revoke_all_user") .Username}}')">{{call $.T "revoke_all"}}</button>
            </form>
            {{end}}
            <a href="/history?user={{.Username}}" class="host-btn">{{call $.T "history"}}</a>
            <form method="POST" action="/api/users/remove" style="display:inline">
              <input type="hidden" name="target_user" value="{{.Username}}">
              <input type="hidden" name="username" value="{{$.Username}}">
              <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
              <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
              <button type="submit" class="host-btn danger" onclick="return confirm('{{call $.T "confirm_remove_user"}}')">{{call $.T "remove_user"}}</button>
            </form>
          </div>
        </div>
        <div class="user-card-meta">
          <span>{{call $.T "active_sessions_count"}}: {{.ActiveSessions}}</span>
          {{if .LastActiveAgo}}<span class="summary-sep">·</span><span class="timestamp">{{.LastActive}}</span><span class="time-ago">{{.LastActiveAgo}}</span>{{end}}
        </div>
        {{if .Sessions}}
        <div class="host-row-users">
          {{range .Sessions}}
          <div class="session-row">
            <span class="row-active">{{.Hostname}} — {{call $.T "time_remaining"}}: {{.Remaining}}</span>
            <div class="session-actions">
              <form method="POST" action="/api/sessions/revoke" style="display:inline">
                <input type="hidden" name="hostname" value="{{.Hostname}}">
                <input type="hidden" name="username" value="{{$.Username}}">
                <input type="hidden" name="session_username" value="{{.SessionUsername}}">
                <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
                <input type="hidden" name="from" value="/admin/users">
                <button type="submit" class="host-btn danger" onclick="return confirm('{{printf (call $.T "confirm_revoke_session") .Hostname}}')">{{call $.T "revoke"}}</button>
              </form>
            </div>
          </div>
          {{end}}
        </div>
        {{end}}
      </div>
      {{end}}
    </div>
    {{else}}
    <p class="empty-state">{{call .T "no_users"}}</p>
    {{end}}

    {{else if eq .AdminTab "groups"}}
    {{if .Groups}}
    <div class="list" role="list">
      {{range .Groups}}
      <div class="row" id="group-{{.Name}}" role="listitem" style="flex-direction:column;align-items:stretch;gap:4px">
        <span class="user-name">{{.Name}}</span>
        <div class="group-card-row">
          <span class="group-card-label">{{call $.T "commands"}}</span>
          {{if .AllCmds}}<span class="summary-chip all">{{call $.T "all_commands"}}</span>
          {{else}}{{range .CmdList}}<span class="pill cmd">{{.}}</span>{{end}}{{end}}
        </div>
        <div class="group-card-row">
          <span class="group-card-label">{{call $.T "hosts"}}</span>
          {{if .AllHosts}}<span class="summary-chip all">{{call $.T "all_hosts"}}</span>
          {{else}}{{range .HostList}}<span class="pill host">{{.}}</span>{{end}}{{end}}
        </div>
        <div class="group-card-row">
          <span class="group-card-label">{{call $.T "sudo_run_as"}}</span>
          <span>{{if .SudoRunAs}}{{.SudoRunAs}}{{else}}—{{end}}</span>
          <span class="summary-sep">·</span>
          <span class="group-card-label">{{call $.T "members"}}</span>
          {{range .Members}}<span class="group-badge">{{.}}</span>{{end}}
        </div>
      </div>
      {{end}}
    </div>
    {{else}}
    <p class="empty-state">{{call .T "no_groups"}}</p>
    {{end}}

    {{else if eq .AdminTab "hosts"}}
    <div class="hosts-toolbar">
      {{if .AllGroups}}
      <div class="group-filter" style="margin-bottom:0">
        <form method="GET" action="/admin/hosts">
          <select name="group" class="col-filter-select" aria-label="{{call .T "aria_filter_group"}}">
            <option value="">{{call .T "all_groups"}}</option>
            {{range .AllGroups}}<option value="{{.}}" {{if eq . $.GroupFilter}}selected{{end}}>{{.}}</option>{{end}}
          </select>
        </form>
        {{if .GroupFilter}}<a href="/admin/hosts" style="font-size:0.813rem;color:var(--text-secondary)">{{call .T "clear_filter"}}</a>{{end}}
      </div>
      {{end}}
      <button id="install-copy-btn" class="host-btn primary" style="margin-left:auto" data-cmd="curl -fsSL {{.InstallURL}} | sudo bash" title="{{call .T "install_client_title"}}"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px;margin-right:5px"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>{{call .T "install_client"}}</button>
      {{if .DeployEnabled}}<button id="deploy-open-btn" class="host-btn primary" title="{{call .T "deploy_title"}}">{{call .T "deploy_btn"}}</button>{{end}}
    </div>

    {{if .Hosts}}
    <div class="list" role="list" aria-label="{{call .T "known_hosts"}}">
      {{range .Hosts}}
      <div class="row" role="listitem" style="flex-direction:column;align-items:stretch;gap:0">
        <div class="host-row-header">
          <div class="host-row-header-info">
            <span class="row-host" style="display:inline">{{.Hostname}}{{if .Group}}<span class="host-group">{{.Group}}</span>{{end}}</span>
            {{if .Escrowed}}<span class="row-sub" style="display:inline;font-size:0.75rem">{{if .EscrowExpired}}{{call $.T "breakglass_expired"}} ({{.EscrowAge}} {{call $.T "ago"}}){{else}}{{call $.T "breakglass_escrowed"}} ({{.EscrowAge}} {{call $.T "ago"}}){{end}}</span>{{end}}
          </div>
          <div class="host-row-header-actions">
            {{if .Escrowed}}
            {{if .EscrowLink}}<a href="{{.EscrowLink}}" target="_blank" class="host-btn">View</a>{{end}}
            <form method="POST" action="/api/hosts/rotate" style="display:inline">
              <input type="hidden" name="hostname" value="{{.Hostname}}">
              <input type="hidden" name="username" value="{{$.Username}}">
              <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
              <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
              <button type="submit" class="host-btn" onclick="return confirm('{{printf (call $.T "confirm_rotate_host") .Hostname}}')">{{call $.T "rotate"}}</button>
            </form>
            {{end}}
          </div>
        </div>
        {{if .HostUsers}}
        <div class="host-row-users">
          {{range .HostUsers}}
          <div class="session-row">
            <span class="{{if .Active}}row-active{{else}}row-sub{{end}}">{{.Username}}{{if .Active}} — {{call $.T "sudo_time_remaining"}}: {{.Remaining}}{{else}} — {{call $.T "no_sudo_session"}}{{end}}</span>
            <div class="session-actions">
              {{if .Active}}
              <form method="POST" action="/api/sessions/extend" style="display:inline">
                <input type="hidden" name="hostname" value="{{.Hostname}}">
                <input type="hidden" name="username" value="{{$.Username}}">
                <input type="hidden" name="session_username" value="{{.Username}}">
                <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
                <input type="hidden" name="from" value="/admin/hosts">
                <button type="submit" class="host-btn primary">{{call $.T "extend"}}</button>
              </form>
              <form method="POST" action="/api/sessions/revoke" style="display:inline">
                <input type="hidden" name="hostname" value="{{.Hostname}}">
                <input type="hidden" name="username" value="{{$.Username}}">
                <input type="hidden" name="session_username" value="{{.Username}}">
                <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
                <input type="hidden" name="from" value="/admin/hosts">
                <button type="submit" class="host-btn danger" onclick="return confirm('{{printf (call $.T "confirm_revoke_session_user") .Username .Hostname}}')">{{call $.T "revoke"}}</button>
              </form>
              {{else}}
              <form method="POST" action="/api/hosts/elevate" class="elevate-form">
                <input type="hidden" name="hostname" value="{{.Hostname}}">
                <input type="hidden" name="username" value="{{$.Username}}">
                <input type="hidden" name="target_user" value="{{.Username}}">
                <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
                {{if $.Durations}}
                <div class="seg-btn" role="group" aria-label="{{call $.T "elevate"}}">
                  {{range $.Durations}}<button type="submit" name="duration" value="{{.Value}}">{{.Label}}</button>{{end}}
                </div>
                {{end}}
              </form>
              {{end}}
            </div>
          </div>
          {{end}}
        </div>
        {{end}}
      </div>
      {{end}}
    </div>
    <div class="bulk-actions">
      {{if .HasEscrowedHosts}}
      <form method="POST" action="/api/hosts/rotate-all" style="display:inline">
        <input type="hidden" name="username" value="{{.Username}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
        <button type="submit" class="bulk-btn" onclick="return confirm('{{call .T "confirm_rotate_all"}}')">{{call .T "rotate_all"}}</button>
      </form>
      {{end}}
      <form method="POST" action="/api/sessions/revoke-all" style="display:inline">
        <input type="hidden" name="username" value="{{.Username}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
        <input type="hidden" name="from" value="/admin/hosts">
        <button type="submit" class="bulk-btn danger" onclick="return confirm('{{call .T "confirm_revoke_all"}}')">{{call .T "revoke_all"}}</button>
      </form>
    </div>
    {{else}}
    <p class="empty-state">{{call .T "no_known_hosts"}}</p>
    {{end}}

    {{else if eq .AdminTab "history"}}
    <form method="GET" action="/admin/history" class="search-bar">
      <input type="hidden" name="action" value="{{.ActionFilter}}">
      <input type="hidden" name="hostname" value="{{.HostFilter}}">
      <input type="hidden" name="user" value="{{.UserFilter}}">
      <input type="hidden" name="sort" value="{{.Sort}}">
      <input type="hidden" name="order" value="{{.Order}}">
      <input type="hidden" name="per_page" value="{{.PerPage}}">
      <input type="text" name="q" value="{{.Query}}" placeholder="{{call .T "search"}}" aria-label="{{call .T "search"}}">
    </form>

    {{if .History}}
    <table class="history-table">
      <thead>
        <tr>
          <th scope="col">{{call .T "time"}} <a href="/admin/history?sort=timestamp&order={{if eq .Sort "timestamp"}}{{if eq .Order "desc"}}asc{{else}}desc{{end}}{{else}}desc{{end}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&per_page={{.PerPage}}" class="sort-btn{{if eq .Sort "timestamp"}} active{{end}}" title="{{call .T "sort_by_time"}}">{{if and (eq .Sort "timestamp") (eq .Order "asc")}}&#x25b2;{{else}}&#x25bc;{{end}}</a></th>
          <th scope="col"><form method="GET" action="/admin/history" class="col-filter-form">
  <input type="hidden" name="hostname" value="{{.HostFilter}}">
  <input type="hidden" name="q" value="{{.Query}}">
  <input type="hidden" name="user" value="{{.UserFilter}}">
  <input type="hidden" name="sort" value="{{.Sort}}">
  <input type="hidden" name="order" value="{{.Order}}">
  <input type="hidden" name="per_page" value="{{.PerPage}}">
  <select name="action" class="col-filter-select" aria-label="{{call .T "aria_filter_action"}}">
    <option value="">{{call .T "action_all"}}</option>
    {{range .ActionOptions}}<option value="{{.Value}}" {{if eq .Value $.ActionFilter}}selected{{end}}>{{.Label}}</option>{{end}}
  </select>
</form><a href="/admin/history?sort=action&order={{if eq .Sort "action"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}asc{{end}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&per_page={{.PerPage}}" class="sort-btn{{if eq .Sort "action"}} active{{end}}" title="{{call .T "sort_by_action"}}">{{if and (eq .Sort "action") (eq .Order "asc")}}&#x25b2;{{else}}&#x25bc;{{end}}</a></th>
          <th scope="col"><form method="GET" action="/admin/history" class="col-filter-form">
  <input type="hidden" name="q" value="{{.Query}}">
  <input type="hidden" name="action" value="{{.ActionFilter}}">
  <input type="hidden" name="hostname" value="{{.HostFilter}}">
  <input type="hidden" name="sort" value="{{.Sort}}">
  <input type="hidden" name="order" value="{{.Order}}">
  <input type="hidden" name="per_page" value="{{.PerPage}}">
  <select name="user" class="col-filter-select" aria-label="{{call .T "aria_filter_user"}}">
    <option value="">{{call .T "user_all"}}</option>
    {{range .UserOptions}}<option value="{{.}}" {{if eq . $.UserFilter}}selected{{end}}>{{.}}</option>{{end}}
  </select>
</form><a href="/admin/history?sort=user&order={{if eq .Sort "user"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}asc{{end}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&per_page={{.PerPage}}" class="sort-btn{{if eq .Sort "user"}} active{{end}}">{{if and (eq .Sort "user") (eq .Order "asc")}}&#x25b2;{{else}}&#x25bc;{{end}}</a></th>
          <th scope="col"><form method="GET" action="/admin/history" class="col-filter-form">
  <input type="hidden" name="action" value="{{.ActionFilter}}">
  <input type="hidden" name="q" value="{{.Query}}">
  <input type="hidden" name="user" value="{{.UserFilter}}">
  <input type="hidden" name="sort" value="{{.Sort}}">
  <input type="hidden" name="order" value="{{.Order}}">
  <input type="hidden" name="per_page" value="{{.PerPage}}">
  <select name="hostname" class="col-filter-select" aria-label="{{call .T "aria_filter_hostname"}}">
    <option value="">{{call .T "host_all"}}</option>
    {{range .HostOptions}}<option value="{{.}}" {{if eq . $.HostFilter}}selected{{end}}>{{.}}</option>{{end}}
  </select>
</form><a href="/admin/history?sort=hostname&order={{if eq .Sort "hostname"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}asc{{end}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&per_page={{.PerPage}}" class="sort-btn{{if eq .Sort "hostname"}} active{{end}}" title="{{call .T "sort_by_host"}}">{{if and (eq .Sort "hostname") (eq .Order "asc")}}&#x25b2;{{else}}&#x25bc;{{end}}</a></th>
          <th scope="col">{{call .T "code"}} <a href="/admin/history?sort=code&order={{if eq .Sort "code"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}asc{{end}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&per_page={{.PerPage}}" class="sort-btn{{if eq .Sort "code"}} active{{end}}" title="{{call .T "sort_by_code"}}">{{if and (eq .Sort "code") (eq .Order "asc")}}&#x25b2;{{else}}&#x25bc;{{end}}</a></th>
        </tr>
      </thead>
      <tbody>
        {{range .History}}
        <tr>
          <td class="col-time">
            <span class="timestamp">{{.FormattedTime}}</span>
            <span class="time-ago">({{.TimeAgo}})</span>
          </td>
          <td><span class="history-action {{.Action}}">{{.ActionLabel}}</span>{{if .Actor}} <span class="history-actor">{{call $.T "by"}} {{.Actor}}</span>{{end}}</td>
          <td>{{.Username}}</td>
          <td class="col-host">{{.Hostname}}</td>
          <td class="col-code">{{if .Code}}{{.Code}}{{end}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
    <div class="pagination">
      {{if .HasPrev}}<a href="/admin/history?page={{sub .Page 1}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&sort={{.Sort}}&order={{.Order}}&per_page={{.PerPage}}">&#8592; {{call .T "previous"}}</a>{{end}}
      <span class="page-info">{{call .T "page"}} {{.Page}} {{call .T "of"}} {{.TotalPages}}</span>
      {{if .HasNext}}<a href="/admin/history?page={{add .Page 1}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&user={{.UserFilter}}&sort={{.Sort}}&order={{.Order}}&per_page={{.PerPage}}">{{call .T "next"}} &#8594;</a>{{end}}
      <form method="GET" action="/admin/history" class="page-size-form">
        <input type="hidden" name="action" value="{{.ActionFilter}}">
        <input type="hidden" name="hostname" value="{{.HostFilter}}">
        <input type="hidden" name="user" value="{{.UserFilter}}">
        <input type="hidden" name="sort" value="{{.Sort}}">
        <input type="hidden" name="order" value="{{.Order}}">
        <input type="hidden" name="q" value="{{.Query}}">
        <select name="per_page" class="page-size-select" aria-label="{{call .T "aria_page_size"}}">
          {{range .PerPageOptions}}<option value="{{.}}" {{if eqInt . $.PerPage}}selected{{end}}>{{.}}</option>{{end}}
        </select>
        <button type="submit" class="page-size-btn">{{call .T "go"}}</button>
      </form>
    </div>
    {{else}}
    <p class="empty-state">{{call .T "no_activity"}}</p>
    {{end}}
    {{end}}
  </div>

  {{if .DeployEnabled}}
  <div id="deploy-modal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="deploy-modal-title">
    <div class="modal-box">
      <h3 id="deploy-modal-title">{{call .T "deploy_modal_title"}}</h3>
      <div id="deploy-form-area">
        <div class="modal-row">
          <div class="modal-field">
            <label for="deploy-host">{{call .T "deploy_host"}}</label>
            <input id="deploy-host" type="text" placeholder="192.168.1.10" autocomplete="off" spellcheck="false">
          </div>
          <div class="modal-field" style="max-width:90px">
            <label for="deploy-port">{{call .T "deploy_port"}}</label>
            <input id="deploy-port" type="number" value="22" min="1" max="65535">
          </div>
        </div>
        <div class="modal-row">
          <div class="modal-field">
            <label for="deploy-ssh-user">{{call .T "deploy_ssh_user"}}</label>
            <input id="deploy-ssh-user" type="text" value="root" autocomplete="off" spellcheck="false">
          </div>
          <div class="modal-field">
            <label for="deploy-pocketid-user">{{call .T "deploy_pocketid_user"}}</label>
            <select id="deploy-pocketid-user">
              <option value="">{{call .T "deploy_user_loading"}}</option>
            </select>
          </div>
        </div>
        <div class="modal-field">
          <label>{{call .T "deploy_key"}}</label>
          <div id="deploy-key-empty">
            <div class="key-upload-row">
              <button type="button" class="key-action-btn" id="deploy-key-paste-btn"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>{{call .T "deploy_key_paste"}}</button>
              <label class="key-action-btn" for="deploy-key-file"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg><span>{{call .T "deploy_key_upload"}}</span></label>
              <input type="file" id="deploy-key-file" style="display:none" accept=".pem,.key,.pub,*">
            </div>
            <div id="deploy-key-validating" style="display:none;font-size:0.813rem;color:var(--text-secondary);margin-top:8px">{{call .T "deploy_key_validating"}}</div>
            <div id="deploy-key-invalid" style="display:none;font-size:0.813rem;color:var(--danger);margin-top:8px"></div>
          </div>
          <div id="deploy-key-loaded" style="display:none">
            <div class="key-info-card">
              <div class="key-info-icon">&#10003;</div>
              <div class="key-info-text">
                <div class="key-info-type" id="deploy-key-type"></div>
                <div class="key-info-fp" id="deploy-key-fp"></div>
              </div>
            </div>
            <button type="button" class="key-clear-btn" id="deploy-key-clear-btn">{{call .T "deploy_key_change"}}</button>
          </div>
        </div>
        <div id="deploy-error" style="color:var(--danger);font-size:0.813rem;margin-top:8px;display:none"></div>
        <div class="modal-actions">
          <button type="button" class="host-btn" id="deploy-cancel-btn">{{call .T "cancel"}}</button>
          <button type="button" class="host-btn primary" id="deploy-submit-btn" disabled>{{call .T "deploy_run"}}</button>
        </div>
      </div>
      <div id="deploy-log-area" style="display:none">
        <div id="deploy-log" class="deploy-log visible" role="log" aria-live="polite" aria-label="{{call .T "deploy_title"}}"></div>
        <div id="deploy-status" class="deploy-status"></div>
        <div class="modal-actions" style="margin-top:8px">
          <button type="button" class="host-btn" id="deploy-close-btn">{{call .T "close"}}</button>
        </div>
      </div>
    </div>
  </div>
  {{end}}
</body>
</html>`

const approvalExpiredHTML = `<!DOCTYPE html>
<html lang="{{.Lang}}"{{if eq .Theme "dark"}} class="theme-dark"{{else if eq .Theme "light"}} class="theme-light"{{end}}>
<head>
  <title>{{call .T "request_expired"}}</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>` + sharedCSS + `
    .icon-warning {
      background: var(--warning-bg);
      border: 2px solid var(--warning-border);
      color: var(--warning);
    }
    h2 { color: var(--warning); }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon icon-warning" aria-hidden="true">&#x23f0;</div>
    <h2>{{call .T "request_expired"}}</h2>
    <p>{{call .T "request_expired_message"}}</p>
    <p>{{call .T "request_expired_action"}}</p>
  </div>
</body>
</html>`

// approvalAlreadyHTML uses html/template syntax so the status is safely escaped.
const approvalAlreadyHTML = `<!DOCTYPE html>
<html lang="{{.Lang}}"{{if eq .Theme "dark"}} class="theme-dark"{{else if eq .Theme "light"}} class="theme-light"{{end}}>
<head>
  <title>{{call .T "already_resolved"}}</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>` + sharedCSS + `
    .icon-info {
      background: var(--info-bg);
      border: 2px solid var(--info-border);
      color: var(--primary);
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon icon-info" aria-hidden="true">&#x2139;</div>
    <h2>{{call .T "already_resolved"}}</h2>
    <p>{{printf (call .T "already_resolved_message") .Status}}</p>
  </div>
</body>
</html>`

