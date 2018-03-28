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

	normalize := func(s string) (string, bool) {
		return s, true
	}

	origins := make([]string, len(config.Origins))
	copy(origins, config.Origins)
	if config.IgnoreProto {
		for i := range origins {
			origins[i], _ = removeProto(origins[i])
		}

		normalize = removeProto
	}

	checkOrigin := func(r *http.Request) bool {
		origin := r.Header.Get(header.Origin)
		if origin != "" {
			origin, b := normalize(origin)
			if !b {
				return false
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
			referer, b := normalize(referer)
			if !b {
				return false
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

func removeProto(s string) (string, bool) {
	prefix := strings.Index(s, "://")
	if prefix >= 0 {
		return s[prefix+3:], true
	}
	return s, false
}
