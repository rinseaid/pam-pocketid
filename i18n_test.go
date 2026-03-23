package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTranslationsLoaded(t *testing.T) {
	// All supported languages should be loaded
	for _, lang := range supportedLanguages {
		if _, ok := translations[lang.Code]; !ok {
			t.Errorf("translations for %s (%s) not loaded", lang.Name, lang.Code)
		}
	}
}

func TestTFallbackToEnglish(t *testing.T) {
	tr := T("xx") // unsupported language
	got := tr("app_name")
	if got != "pam-pocketid" {
		t.Errorf("T('xx')('app_name') = %q, want %q", got, "pam-pocketid")
	}
}

func TestTReturnsKeyAsLastResort(t *testing.T) {
	tr := T("en")
	got := tr("nonexistent_key_xyz")
	if got != "nonexistent_key_xyz" {
		t.Errorf("T('en')('nonexistent_key_xyz') = %q, want %q", got, "nonexistent_key_xyz")
	}
}

func TestTSpanish(t *testing.T) {
	tr := T("es")
	got := tr("sessions")
	if got != "Sesiones" {
		t.Errorf("T('es')('sessions') = %q, want %q", got, "Sesiones")
	}
}

func TestDetectLanguageCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "pam_lang", Value: "fr"})
	lang := detectLanguage(r)
	if lang != "fr" {
		t.Errorf("detectLanguage with cookie = %q, want %q", lang, "fr")
	}
}

func TestDetectLanguageAcceptHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept-Language", "de-DE,de;q=0.9,en;q=0.8")
	lang := detectLanguage(r)
	if lang != "de" {
		t.Errorf("detectLanguage with Accept-Language = %q, want %q", lang, "de")
	}
}

func TestDetectLanguageDefault(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	lang := detectLanguage(r)
	if lang != "en" {
		t.Errorf("detectLanguage default = %q, want %q", lang, "en")
	}
}

func TestDetectLanguageCookiePriority(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "pam_lang", Value: "ja"})
	r.Header.Set("Accept-Language", "de-DE")
	lang := detectLanguage(r)
	if lang != "ja" {
		t.Errorf("detectLanguage cookie should take priority, got %q, want %q", lang, "ja")
	}
}

func TestSetLanguageCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/hosts?lang=es", nil)
	w := httptest.NewRecorder()
	redirected := setLanguageCookie(w, r)
	if !redirected {
		t.Error("setLanguageCookie should return true for valid lang param")
	}
	// Check the cookie was set
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "pam_lang" && c.Value == "es" {
			found = true
		}
	}
	if !found {
		t.Error("pam_lang cookie not set")
	}
}

func TestTerminalLang(t *testing.T) {
	// Default should be "en"
	lang := terminalLang()
	// We can't predict the test environment's LANG, but the function should not panic
	_ = lang
}

func TestAllTranslationKeysConsistent(t *testing.T) {
	// All languages should have the same keys as English
	enKeys := translations["en"]
	for _, lang := range supportedLanguages {
		if lang.Code == "en" {
			continue
		}
		tr, ok := translations[lang.Code]
		if !ok {
			continue
		}
		for key := range enKeys {
			if _, ok := tr[key]; !ok {
				t.Errorf("language %s missing key %q", lang.Code, key)
			}
		}
	}
}
