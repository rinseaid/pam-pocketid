package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	challengesCreated = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "pam_pocketid",
		Name:      "challenges_created_total",
		Help:      "Total number of sudo challenges created.",
	})

	challengesApproved = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "pam_pocketid",
		Name:      "challenges_approved_total",
		Help:      "Total number of sudo challenges approved via OIDC authentication.",
	})

	challengesAutoApproved = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "pam_pocketid",
		Name:      "challenges_auto_approved_total",
		Help:      "Total number of sudo challenges auto-approved via grace period.",
	})

	challengesDenied = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pam_pocketid",
		Name:      "challenges_denied_total",
		Help:      "Total number of sudo challenges denied.",
	}, []string{"reason"})

	challengesExpired = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "pam_pocketid",
		Name:      "challenges_expired_total",
		Help:      "Total number of sudo challenges that expired without resolution.",
	})

	challengeDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "pam_pocketid",
		Name:      "challenge_duration_seconds",
		Help:      "Time from challenge creation to resolution (approval or denial).",
		Buckets:   []float64{5, 10, 15, 30, 45, 60, 90, 120},
	})

	rateLimitRejections = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "pam_pocketid",
		Name:      "rate_limit_rejections_total",
		Help:      "Total number of challenge creation requests rejected due to rate limiting.",
	})

	authFailures = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "pam_pocketid",
		Name:      "auth_failures_total",
		Help:      "Total number of requests rejected due to invalid shared secret.",
	})

	activeChallenges = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "pam_pocketid",
		Name:      "active_challenges",
		Help:      "Number of currently active (pending) challenges.",
	})

	breakglassEscrowTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pam_pocketid",
		Name:      "breakglass_escrow_total",
		Help:      "Total number of break-glass password escrow operations.",
	}, []string{"status"})

	notificationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pam_pocketid",
		Name:      "notifications_total",
		Help:      "Total number of push notification attempts.",
	}, []string{"status"}) // status: sent, failed, skipped

	graceSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "pam_pocketid",
		Name:      "grace_sessions_active",
		Help:      "Current number of active grace period sessions.",
	})

	oidcExchangeDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "pam_pocketid",
		Name:      "oidc_exchange_duration_seconds",
		Help:      "Time spent on OIDC token exchange with the identity provider.",
		Buckets:   []float64{0.1, 0.25, 0.5, 1, 2, 5, 15},
	})

	registeredHosts = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "pam_pocketid",
		Name:      "registered_hosts",
		Help:      "Number of hosts registered in the host registry.",
	})
)

func init() {
	notificationsTotal.WithLabelValues("sent")
	notificationsTotal.WithLabelValues("failed")
	notificationsTotal.WithLabelValues("skipped")
	breakglassEscrowTotal.WithLabelValues("success")
	breakglassEscrowTotal.WithLabelValues("failure")
	challengesDenied.WithLabelValues("oidc_error")
	challengesDenied.WithLabelValues("nonce_mismatch")
	challengesDenied.WithLabelValues("identity_mismatch")
	challengesDenied.WithLabelValues("user_rejected")
}
