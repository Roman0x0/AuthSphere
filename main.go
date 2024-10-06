package main

import (
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/dvwright/xss-mw"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func keyFunc(c *gin.Context) string {
	return c.ClientIP()
}

func errorHandler(c *gin.Context, info Info) {
	c.String(429, "Too many requests. Try again in "+time.Until(info.ResetTime).String())
}

func HandleIPDebug(c *gin.Context) {
	clientIP := c.Request.Header.Get("X-Forwarded-For")
	c.String(200, "Clients IP: "+clientIP+"\nGoIP: "+c.ClientIP())
}

func main() {
	// load settings
	rand.Seed(time.Now().UnixNano())
	LoadSettings()
	InitDB()

	gin.SetMode(gin.ReleaseMode)
	frontendServer := gin.Default()

	frontendServer.SetTrustedProxies(nil)

	frontendServer.TrustedPlatform = "X-Forwarded-For"

	storeReq := InMemoryStore(&InMemoryOptions{
		Rate:  time.Second,
		Limit: 6,
	})
	mw := RateLimiter(storeReq, &Options{
		ErrorHandler: errorHandler,
		KeyFunc:      keyFunc,
	})

	xssMdlwr := &xss.XssMw{
		FieldsToSkip: []string{"password"},
		BmPolicy:     "UGCPolicy",
	}
	frontendServer.Use(xssMdlwr.RemoveXss())

	store := cookie.NewStore([]byte(settings.SessionSecret))

	store.Options(sessions.Options{Secure: true, HttpOnly: true, MaxAge: 7200})
	frontendServer.Use(sessions.Sessions(settings.SessionName, store))
	frontendServer.Use(CSRFProtection(csrfOptions{
		Secret: settings.CSRFSecret,
		ErrorFunc: func(c *gin.Context) {
			c.String(400, "CSRF token mismatch")
			c.Abort()
		},
	}))

	frontendServer.Use(gin.Recovery())

	// check db
	if !CheckDBOnline() {
		log.Fatal("Database is offline")
		return
	}

	frontendServer.LoadHTMLGlob("content/pages/*.html")
	frontendServer.Static("/style", "content/style")
	frontendServer.Static("/images", "content/images")
	frontendServer.Static("/js", "content/js")

	frontendServer.GET("/", mw, HandleIndex)
	frontendServer.GET("/pricing", mw, HandlePricing)
	frontendServer.GET("/terms-of-service", mw, HandleTermsOfService)
	frontendServer.GET("/documentation", mw, HandleDocumentation)

	frontendServer.GET("/sign-in", mw, HandleLogin)
	frontendServer.GET("/sign-out", mw, HandleSignOut)
	frontendServer.GET("/pwd-recovery", mw, HandleRecovery)
	frontendServer.GET("/sign-up", mw, HandleRegister)
	frontendServer.GET("/verify/:username/:pass", mw, HandleVerify)
	frontendServer.GET("/recover-account/:username/:pass", mw, AccountRecoveryHandler)
	frontendServer.POST("/change-password", mw, AccountPasswordChangeHandler)

	frontendServer.POST("/sign-up", mw, HandleSignUp)
	frontendServer.POST("/pwd-recovery", mw, HandlePwdRecovery)
	frontendServer.POST("/sign-in", mw, HandleSignIn)

	// panel
	frontendServer.GET("/panel/dashboard", mw, HandleDashboard)
	frontendServer.GET("/panel/account", mw, HandleAccount)
	frontendServer.GET("/panel/account/request-verification", mw, HandleAccountVerify)
	frontendServer.GET("/upgrade", mw, HandleUpgradeAccount)
	frontendServer.GET("/panel/logs", mw, HandleLogs)

	// panel post
	frontendServer.POST("/panel/dashboard/new-keypair", mw, HandleDashboardUpdateKeyPair)
	frontendServer.POST("/panel/dashboard/new-secret", mw, HandleDashboardUpdateSecret)
	frontendServer.POST("/panel/dashboard/remove", mw, HandleDashboardRemoveApp)
	frontendServer.POST("/panel/dashboard/update", mw, HandleDashboardUpdateAppName)
	frontendServer.POST("/panel/dashboard/create", mw, HandleDashboardCreateNewApp)

	// panel account post
	frontendServer.POST("/panel/account/2fa/*action", mw, HandleAccount2FA)

	// panel applications
	frontendServer.GET("/panel/dashboard/app/:secret", mw, HandleAppOverview)
	frontendServer.GET("/panel/dashboard/app/:secret/licenses", mw, HandleAppLicenses)
	frontendServer.GET("/panel/dashboard/app/:secret/users", mw, HandleAppUsers)
	frontendServer.GET("/panel/dashboard/app/:secret/variables", mw, HandleAppVariables)
	frontendServer.GET("/panel/dashboard/app/:secret/blacklists", mw, HandleAppBlacklists)
	frontendServer.GET("/panel/dashboard/app/:secret/settings", mw, HandleAppSettings)
	frontendServer.GET("/panel/dashboard/app/:secret/logs", mw, HandleAppLogs)

	// panel license stuff
	frontendServer.POST("/panel/dashboard/app/licenses", mw, HandleManageAppLicenses)
	frontendServer.POST("/panel/dashboard/app/licenses/download", mw, HandleManageAppLicensesDownload)

	// panel user stuff
	frontendServer.POST("/panel/dashboard/app/users", mw, HandleManageAppUsers)

	// panel variable stuff
	frontendServer.POST("/panel/dashboard/app/variables", mw, HandleManageAppVariables)

	// panel blacklist stuff
	frontendServer.POST("/panel/dashboard/app/blacklists", mw, HandleManageAppBlacklists)

	// panel settings stuff
	frontendServer.POST("/panel/dashboard/app/settings", mw, HandleAppSettingsSave)

	// panel log stuff
	frontendServer.POST("/panel/dashboard/app/logs", mw, HandleManageAppLogs)

	// admin stuff
	frontendServer.GET("/admin", mw, HandleAdmin)

	// 404
	frontendServer.NoRoute(func(c *gin.Context) {
		c.Redirect(http.StatusPermanentRedirect, "/")
	})

	frontendServer.Run(":5555")
}
