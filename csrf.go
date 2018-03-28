package csrf

import (
	"net/http"
	"strings"

	"github.com/acoshift/header"
	"github.com/acoshift/middleware"
)

// Config is the csrf config
type Config struct {
	Origins          []string
	ForbiddenHandler http.Handler
	IgnoreProto      bool
}

// New creates new csrf middleware
func New(config Config) middleware.Middleware {
	if config.ForbiddenHandler == nil {
		config.ForbiddenHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Forbidden", http.StatusForbidden)
		})
	}

	origins := make([]string, len(config.Origins))
	copy(origins, config.Origins)
	if config.IgnoreProto {
		for i := range origins {
			origins[i] = removeProto(origins[i])
		}
	}

	checkOrigin := func(r *http.Request) bool {
		origin := r.Header.Get(header.Origin)
		if origin != "" {
			if config.IgnoreProto {
				l := len(origin)
				origin = removeProto(origin)
				if l == len(origin) {
					return false
				}
			}
			for _, allow := range origins {
				if origin == allow {
					return true
				}
			}
		}

		return false
	}

	checkReferer := func(r *http.Request) bool {
		referer := r.Referer()
		if referer != "" {
			if config.IgnoreProto {
				l := len(referer)
				referer = removeProto(referer)
				if l == len(referer) {
					return false
				}
			}
			for _, allow := range origins {
				if strings.HasPrefix(referer, allow+"/") {
					return true
				}
			}
		}
		return false
	}

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				if !checkOrigin(r) && !checkReferer(r) {
					config.ForbiddenHandler.ServeHTTP(w, r)
					return
				}
			}
			h.ServeHTTP(w, r)
		})
	}
}

func removeProto(s string) string {
	prefix := strings.Index(s, "://")
	if prefix >= 0 {
		return s[prefix+3:]
	}
	return s
}
