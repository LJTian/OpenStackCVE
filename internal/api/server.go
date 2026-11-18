package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"OpenStackCVE/internal/db"
	"OpenStackCVE/internal/model"
)

// Server exposes CVE query APIs over Gin.
type Server struct {
	DB *db.DB
}

// NewRouter builds the Gin engine.
func NewRouter(database *db.DB) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())

	s := &Server{DB: database}
	r.GET("/", s.handleIndex)
	r.GET("/healthz", s.handleHealth)
	r.GET("/api/health", s.handleHealth)
	r.GET("/api/cves", s.handleListCVEs)
	r.GET("/api/cves/:cve_id", s.handleGetCVE)
	return r
}

func (s *Server) handleIndex(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"service": "os-cve-cache",
		"endpoints": []gin.H{
			{"method": "GET", "path": "/api/health", "desc": "health check"},
			{"method": "GET", "path": "/api/cves", "desc": "list/filter CVEs (?cve_id=&component=&since=&severity=&limit=)"},
			{"method": "GET", "path": "/api/cves/:cve_id", "desc": "get one CVE by id"},
		},
	})
}

func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) handleListCVEs(c *gin.Context) {
	limit := 100
	if v := c.Query("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid limit"})
			return
		}
		limit = n
	}

	items, err := s.DB.Query(c.Request.Context(), db.QueryFilter{
		CVEID:     c.Query("cve_id"),
		Component: c.Query("component"),
		Since:     c.Query("since"),
		Severity:  c.Query("severity"),
		Limit:     limit,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.QueryResult{Count: len(items), Items: items})
}

func (s *Server) handleGetCVE(c *gin.Context) {
	cveID := c.Param("cve_id")
	items, err := s.DB.Query(c.Request.Context(), db.QueryFilter{
		CVEID: cveID,
		Limit: 1,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(items) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found", "cve_id": cveID})
		return
	}
	c.JSON(http.StatusOK, items[0])
}
