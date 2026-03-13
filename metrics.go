package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	challengesCreated = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pam_pocketid",
		Name:      "challenges_created_total",
		Help:      "Total number of sudo challenges created.",
	}, []string{"username"})

	challengesApproved = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "pam_pocketid",
		Name:      "challenges_approved_total",
		Help:      "Total number of sudo challenges approved.",
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
)
