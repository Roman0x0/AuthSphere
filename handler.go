package main

import (
	"log"
	"net/http"
	"strconv"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	csrf "github.com/utrack/gin-csrf"
	"golang.org/x/crypto/bcrypt"
)

func HandleIndex(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title": settings.SiteName,
		"first": settings.SiteNameFirst,
		"last":  settings.SiteNameLast,
	})
}

func HandleTermsOfService(c *gin.Context) {
	c.HTML(http.StatusOK, "tos.html", gin.H{
		"title": settings.SiteName,
		"first": settings.SiteNameFirst,
		"last":  settings.SiteNameLast,
	})
}

func HandleDocumentation(c *gin.Context) {
	c.HTML(http.StatusOK, "documentation.html", gin.H{
		"title": settings.SiteName,
		"first": settings.SiteNameFirst,
		"last":  settings.SiteNameLast,
	})
}

func HandlePricing(c *gin.Context) {
	c.HTML(http.StatusOK, "pricing.html", gin.H{
		"title": settings.SiteName,
		"first": settings.SiteNameFirst,
		"last":  settings.SiteNameLast,
	})
}

func HandleLogin(c *gin.Context) {
	// csrf
	csrf := GetToken(c)
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if sessionName != nil {
		exists, err := UserExists(sessionName.(string))
		if err != nil {
			panic(err)
		}

		if exists {
			c.Redirect(http.StatusPermanentRedirect, "/panel/dashboard")
		}
	}

	c.HTML(http.StatusOK, "login.html", gin.H{
		"title":      settings.SiteName,
		"first":      settings.SiteNameFirst,
		"last":       settings.SiteNameLast,
		"MsgOnError": "",
		"color":      "",
		"csrf":       csrf,
	})

}

func HandleAdmin(c *gin.Context) {
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	if currentUser.Group != "admin" {
		c.Redirect(http.StatusPermanentRedirect, "/")
		return
	}

	subCount, err := TotalSubscriptionCountAuthSphere()
	if err != nil {
		panic(err)
	}

	registered, err := TotalUserCountRegisteredAuthSphere()
	if err != nil {
		panic(err)
	}

	verified, err := TotalUserCountVerifiedAuthSphere()
	if err != nil {
		panic(err)
	}

	c.HTML(http.StatusOK, "admin.html", gin.H{
		"title":                settings.SiteName,
		"first":                settings.SiteNameFirst,
		"last":                 settings.SiteNameLast,
		"username":             currentUser.Username,
		"totalRegisteredUsers": registered,
		"totalVerifiedUsers":   verified,
		"totalSubscriptions":   subCount,
	})
}

func HandleRegister(c *gin.Context) {
	// gets csrf token
	csrf := csrf.GetToken(c)

	c.HTML(http.StatusOK, "register.html", gin.H{
		"title":      settings.SiteName,
		"first":      settings.SiteNameFirst,
		"last":       settings.SiteNameLast,
		"csrf":       csrf,
		"MsgOnError": "",
		"color":      "",
		"boxheight":  "670px",
	})
}

func HandleSignOut(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()

	c.Redirect(http.StatusTemporaryRedirect, "/sign-in")
}

// REQUIRES AUTH

func HandleAppSettingsSave(c *gin.Context) {
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	secret := c.PostForm("secret")

	app, err := GetApplication(currentUser, secret)
	if err != nil {
		panic(err)
	}

	if (Application{} == app) { // app doesn't exist or isnt owned by user
		c.Redirect(http.StatusPermanentRedirect, "/panel/dashboard")
		return
	}

	enableIntegrityCheck := c.PostForm("checkBoxEnableIntegrity")
	if enableIntegrityCheck == "on" {
		enableIntegrityCheck = "1"
	} else {
		enableIntegrityCheck = "0"
	}

	applicationHash := c.PostForm("applicationHash")

	enableAppUpdates := c.PostForm("checkBoxEnableUpdates")
	if enableAppUpdates == "on" {
		enableAppUpdates = "1"
	} else {
		enableAppUpdates = "0"
	}

	applicationVersion := c.PostForm("applicationVersion")
	applicationUpdateLink := c.PostForm("applicationUpdateLink")

	applicationStatus := c.PostForm("checkBoxPauseApplication")
	if app.Status != "locked" {
		if applicationStatus == "on" {
			applicationStatus = "paused"
		} else {
			applicationStatus = "active"
		}
	} else {
		applicationStatus = "locked"
	}

	enableAntiVPN := c.PostForm("checkBoxAntiVPN")

	if enableAntiVPN == "on" {
		// check if user is free or not and enable / disable accordingly
		if !user_allowed_antivpn {
			if currentUser.Active_Plan == "free" {
				enableAntiVPN = "0"
			} else {
				enableAntiVPN = "1"
			}
		} else {
			enableAntiVPN = "1"
		}
	} else {
		enableAntiVPN = "0"
	}

	err = UpdateApplicationSettings(enableAntiVPN, enableIntegrityCheck, applicationHash, enableAppUpdates, applicationVersion, applicationUpdateLink, applicationStatus, currentUser, app)
	if err != nil {
		log.Println(err.Error())
	}

	c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/settings")
}

//// SETTINGS SECTION ////

// // USER MANAGEMENT SECTION ////
// REQUIRES AUTH

func HandleManageAppUsers(c *gin.Context) {
	csrf := GetToken(c)
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	secret := c.PostForm("secret")

	app, err := GetApplication(currentUser, secret)
	if err != nil {
		panic(err)
	}

	if (Application{} == app) { // app doesn't exist or isnt owned by user
		c.Redirect(http.StatusPermanentRedirect, "/panel/dashboard")
		return
	}

	action := c.PostForm("action")

	switch action {
	case "remove-all": // remove all users
		err := RemoveAllUsers(app)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/users")
	case "reset-all-hwids": // reset all hwids
		err := ResetAllHWIDs(app)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/users")
	case "remove-all-expired": // remove all expired users
		err := RemoveAllExpiredUsers(app)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/users")
	case "create": // creates new user
		usernameNew := c.PostForm("userUsername")
		passwordNew := c.PostForm("userPassword")

		if usernameNew == "" || passwordNew == "" {
			break
		}

		if containsForbiddenCharacters(usernameNew) {
			users, err := GetUsers(app.Secret)
			if err != nil {
				panic(err)
			}

			c.HTML(http.StatusOK, "users.html", gin.H{
				"title":      settings.SiteName,
				"first":      settings.SiteNameFirst,
				"last":       settings.SiteNameLast,
				"appName":    app.Name,
				"username":   currentUser.Username,
				"Secret":     secret,
				"Users":      users,
				"userColor":  settings.ErrorColor,
				"MsgOnError": "invalid_format",
				"csrf":       csrf,
			})
			return
		}

		userExists, err := AppUserExists(usernameNew, app)
		if err != nil {
			panic(err)
		}

		users, err := GetUsers(app.Secret)
		if err != nil {
			panic(err)
		}

		if userExists {
			c.HTML(http.StatusOK, "users.html", gin.H{
				"title":      settings.SiteName,
				"first":      settings.SiteNameFirst,
				"last":       settings.SiteNameLast,
				"appName":    app.Name,
				"username":   currentUser.Username,
				"Secret":     secret,
				"Users":      users,
				"userColor":  settings.ErrorColor,
				"MsgOnError": "user_exists",
				"csrf":       csrf,
			})
			return
		}

		// check if premium user or not
		// if not user is allowed to only have specific amount of users
		if currentUser.Active_Plan == "free" {
			if len(users) >= user_application_user_limit {
				c.HTML(http.StatusOK, "users.html", gin.H{
					"title":      settings.SiteName,
					"first":      settings.SiteNameFirst,
					"last":       settings.SiteNameLast,
					"appName":    app.Name,
					"username":   currentUser.Username,
					"Secret":     secret,
					"Users":      users,
					"userColor":  settings.ErrorColor,
					"MsgOnError": "user_limit_reached",
					"csrf":       csrf,
				})
				return
			}
		}

		err = AddAppUser(app, usernameNew, passwordNew)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/users")
	case "remove":
		username := c.PostForm("username")

		err = RemoveUser(app, username)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/users")
	case "reset-hwid":
		username := c.PostForm("username")

		err = ResetUserHWID(app, username)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/users")
	case "update":
		username := c.PostForm("username")

		appUser, err := GetApplicationUser(secret, username)
		if err != nil {
			panic(err)
		}

		if (Application_User{} == appUser) { // user doesn't exist
			c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/users")
			return
		}

		password := c.PostForm("password")
		email := c.PostForm("email")
		ip := c.PostForm("ip")
		expires := c.PostForm("expires")
		hwid := c.PostForm("hwid")
		last_login := c.PostForm("last_login")
		created_at := c.PostForm("created_at")
		variable := c.PostForm("variable")
		banned := c.PostForm("banned")
		level := c.PostForm("level")

		err = UpdateAppUser(appUser, email, ip, password, expires, hwid, last_login, created_at, banned, variable, level)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/users")
	case "edit":
		username := c.PostForm("username")

		appUser, err := GetApplicationUser(secret, username)
		if err != nil {
			panic(err)
		}

		if (Application_User{} == appUser) { // user doesn't exist
			c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/users")
			return
		}

		c.HTML(http.StatusOK, "edituser.html", gin.H{
			"title":      settings.SiteName,
			"first":      settings.SiteNameFirst,
			"last":       settings.SiteNameLast,
			"appName":    app.Name,
			"username":   appUser.Username,
			"email":      appUser.Email,
			"ip":         appUser.IP,
			"expires":    appUser.Exp_Date,
			"hwid":       appUser.HWID,
			"last_login": appUser.Last_Login,
			"created_at": appUser.Created_At,
			"banned":     appUser.Banned,
			"var":        appUser.Variable,
			"level":      appUser.Level,
			"Secret":     secret,
			"csrf":       csrf,
		})
		return
	case "ban":
		username := c.PostForm("username")

		err := BanUser(secret, username)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/users")
	default:
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/users")
	}

}

func HandleManageAppLogs(c *gin.Context) {
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	secret := c.PostForm("secret")

	app, err := GetApplication(currentUser, secret)
	if err != nil {
		panic(err)
	}

	if (Application{} == app) { // app doesn't exist or isnt owned by user
		c.Redirect(http.StatusPermanentRedirect, "/panel/dashboard")
		return
	}

	action := c.PostForm("action")

	switch action {
	case "remove":
		logid := c.PostForm("id")

		err := RemoveLog(app, logid)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/logs")

	case "remove-all":
		err = RemoveAllLogs(app)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/logs")

	default:
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/logs")
	}
}

func HandleManageAppVariables(c *gin.Context) {
	csrf := GetToken(c)

	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	secret := c.PostForm("secret")

	app, err := GetApplication(currentUser, secret)
	if err != nil {
		panic(err)
	}

	if (Application{} == app) { // app doesn't exist or isnt owned by user
		c.Redirect(http.StatusPermanentRedirect, "/panel/dashboard")
		return
	}

	action := c.PostForm("action")

	switch action {
	case "update":
		varSecret := c.PostForm("currentSecret")

		newValue := c.PostForm("newValue")

		err := UpdateAppVariable(varSecret, newValue)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/variables")
	case "edit":
		variable := c.PostForm("variable")

		appVariable, err := GetApplicationVariable(secret, variable)
		if err != nil {
			panic(err)
		}

		if (Variable{} == appVariable) { // variable doesn't exist
			c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/variables")
			return
		}

		c.HTML(http.StatusOK, "editvariable.html", gin.H{
			"title":          settings.SiteName,
			"first":          settings.SiteNameFirst,
			"last":           settings.SiteNameLast,
			"appName":        app.Name,
			"username":       currentUser.Username,
			"variableName":   appVariable.Variable_Name,
			"variableValue":  appVariable.Variable_Value,
			"variableSecret": appVariable.Variable_Secret,
			"Secret":         secret,
			"csrf":           csrf,
		})
		return
	case "remove":
		variable := c.PostForm("variable")

		err = RemoveVariable(app, variable)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/variables")
	case "remove-all":
		err = RemoveAllVariables(app)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/variables")
	case "create":
		variableName := c.PostForm("variableName")
		variableValue := c.PostForm("variableValue")

		// check if premium user or not
		// if not user is allowed to create only a certain variable limit
		if currentUser.Active_Plan == "free" {

			variables, err := GetVariables(app.Secret)
			if err != nil {
				panic(err)
			}

			if len(variables) >= user_application_variable_limit {
				c.HTML(http.StatusOK, "variables.html", gin.H{
					"title":      settings.SiteName,
					"first":      settings.SiteNameFirst,
					"last":       settings.SiteNameLast,
					"appName":    app.Name,
					"username":   currentUser.Username,
					"Secret":     secret,
					"Variables":  variables,
					"MsgOnError": "create_limit",
					"csrf":       csrf,
				})
				return
			}
		}

		err = AddVariableToApp(app.Secret, variableName, variableValue)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/variables")
	default:
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/variables")
	}
}

func HandleManageAppLicensesDownload(c *gin.Context) {
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	secret := c.PostForm("secret")

	app, err := GetApplication(currentUser, secret)
	if err != nil {
		panic(err)
	}

	if (Application{} == app) { // app doesn't exist or isnt owned by user
		c.Redirect(http.StatusPermanentRedirect, "/panel/dashboard")
		return
	}

	licenses, err := GetLicenses(secret)
	if err != nil {
		panic(err)
	}

	if len(licenses) != 0 {
		final := ""

		for _, license := range licenses {
			final += license.License + "\n"
		}

		contentLength := strconv.Itoa(len(final))

		c.Writer.Header().Set("Content-Description", "License File Download")
		c.Writer.Header().Set("Content-Type", "application/octet-stream")
		c.Writer.Header().Set("Content-Disposition", " attachment; filename=\"licenses.txt\"")
		c.Writer.Header().Set("Cache-Control", "must-revalidate")
		c.Writer.Header().Set("Pragma", "public")
		c.Writer.Header().Set("Expires", "0")
		c.Writer.Header().Set("Content-Length", contentLength)
		c.String(http.StatusOK, "%v", final)
	}
	c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/licenses")
}

func HandleManageAppLicenses(c *gin.Context) {
	// GET csrf
	csrf := GetToken(c)

	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	secret := c.PostForm("secret")

	app, err := GetApplication(currentUser, secret)
	if err != nil {
		panic(err)
	}

	if (Application{} == app) { // app doesn't exist or isnt owned by user
		c.Redirect(http.StatusPermanentRedirect, "/panel/dashboard")
		return
	}

	action := c.PostForm("action")

	switch action {
	case "remove-all":
		err = RemoveAllLicenses(app)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/licenses")
	case "remove-all-used":
		err = RemoveAllUsedLicenses(app)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/licenses")
	case "remove-all-unused":
		err = RemoveAllUnusedLicenses(app)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/licenses")
	case "create": // create new licenses
		licenseAmount := c.PostForm("licenseAmount")
		licensePrefix := c.PostForm("licensePrefix")
		licenseLength := c.PostForm("licenseLength")
		licenseExpiration := c.PostForm("licenseExpiration")
		licenseLevel := c.PostForm("licenseLevel")
		format := c.PostForm("licenseFormat")

		convertedAmount, _ := strconv.Atoi(licenseAmount)
		convertedLength, _ := strconv.Atoi(licenseLength)

		if containsForbiddenCharacters(licensePrefix) {
			licenses, err := GetLicenses(app.Secret)
			if err != nil {
				panic(err)
			}

			c.HTML(http.StatusOK, "licenses.html", gin.H{
				"title":      settings.SiteName,
				"first":      settings.SiteNameFirst,
				"last":       settings.SiteNameLast,
				"appName":    app.Name,
				"username":   currentUser.Username,
				"Secret":     secret,
				"Licenses":   licenses,
				"MsgOnError": "invalid_format",
				"csrf":       csrf,
			})
			return
		}

		// check if premium user or not
		// if not user is allowed to create only a certain license limit at a time and also has to use the set prefix
		if currentUser.Active_Plan == "free" {

			licenses, err := GetLicenses(app.Secret)
			if err != nil {
				panic(err)
			}

			if len(licenses) >= 30 {
				c.HTML(http.StatusOK, "licenses.html", gin.H{
					"title":      settings.SiteName,
					"first":      settings.SiteNameFirst,
					"last":       settings.SiteNameLast,
					"appName":    app.Name,
					"username":   currentUser.Username,
					"Secret":     secret,
					"Licenses":   licenses,
					"MsgOnError": "total_create_limit",
					"csrf":       csrf,
				})
				return
			}

			if convertedAmount > user_license_create_limit {
				c.HTML(http.StatusOK, "licenses.html", gin.H{
					"title":      settings.SiteName,
					"first":      settings.SiteNameFirst,
					"last":       settings.SiteNameLast,
					"appName":    app.Name,
					"username":   currentUser.Username,
					"Secret":     secret,
					"Licenses":   licenses,
					"MsgOnError": "create_limit",
					"csrf":       csrf,
				})
				return
			}

			if licensePrefix != "AuthSphere" {
				c.HTML(http.StatusOK, "licenses.html", gin.H{
					"title":      settings.SiteName,
					"first":      settings.SiteNameFirst,
					"last":       settings.SiteNameLast,
					"appName":    app.Name,
					"username":   currentUser.Username,
					"Secret":     secret,
					"Licenses":   licenses,
					"MsgOnError": "prefix_required",
					"csrf":       csrf,
				})
				return
			}

			if convertedLength != 16 {
				c.HTML(http.StatusOK, "licenses.html", gin.H{
					"title":      settings.SiteName,
					"first":      settings.SiteNameFirst,
					"last":       settings.SiteNameLast,
					"appName":    app.Name,
					"username":   currentUser.Username,
					"Secret":     secret,
					"Licenses":   licenses,
					"MsgOnError": "length_limit",
					"csrf":       csrf,
				})
				return
			}

			if format == "XXXX-XXXX-XXXX-XXXX" {
				c.HTML(http.StatusOK, "licenses.html", gin.H{
					"title":      settings.SiteName,
					"first":      settings.SiteNameFirst,
					"last":       settings.SiteNameLast,
					"appName":    app.Name,
					"username":   currentUser.Username,
					"Secret":     secret,
					"Licenses":   licenses,
					"MsgOnError": "format_limit",
					"csrf":       csrf,
				})
				return
			}
		}

		err = AddLicensesToApp(currentUser, convertedAmount, convertedLength, secret, licensePrefix, licenseExpiration, licenseLevel, format)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/licenses")
	case "unuse":
		license := c.PostForm("license")

		err = UnuseLicense(app, license)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/licenses")
	case "remove":
		license := c.PostForm("license")

		err = RemoveLicense(app, license)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/licenses")
	default:
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/licenses")
	}
}

// REQUIRES AUTH
func HandleAppLogs(c *gin.Context) {
	// csrf
	csrf := GetToken(c)
	// Check for active session, if doesn't exist force user to login
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	secret := c.Param("secret")

	app, err := GetApplication(currentUser, secret)
	if err != nil {
		panic(err)
	}

	if (Application{} == app) { // app doesn't exist or isnt owned by user
		c.Redirect(http.StatusPermanentRedirect, "/panel/dashboard")
		return
	}

	logs, err := GetApplicationLogs(app)
	if err != nil {
		panic(err)
	}

	c.HTML(http.StatusOK, "app_logs.html", gin.H{
		"title":    settings.SiteName,
		"first":    settings.SiteNameFirst,
		"last":     settings.SiteNameLast,
		"appName":  app.Name,
		"username": currentUser.Username,
		"Secret":   secret,
		"Logs":     logs,
		"csrf":     csrf,
	})
}

// REQUIRES AUTH
func HandleAppSettings(c *gin.Context) {
	// csrf
	csrf := GetToken(c)
	// Check for active session, if doesn't exist force user to login
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	secret := c.Param("secret")

	app, err := GetApplication(currentUser, secret)
	if err != nil {
		panic(err)
	}

	if (Application{} == app) { // app doesn't exist or isnt owned by user
		c.Redirect(http.StatusPermanentRedirect, "/panel/dashboard")
		return
	}

	var checkBoxAntiVPNEnabled string
	if currentUser.Active_Plan == "free" {
		checkBoxAntiVPNEnabled = "disabled"
	}

	c.HTML(http.StatusOK, "settings.html", gin.H{
		"title":                settings.SiteName,
		"first":                settings.SiteNameFirst,
		"last":                 settings.SiteNameLast,
		"appName":              app.Name,
		"username":             currentUser.Username,
		"Secret":               secret,
		"appHash":              app.Application_Hash,
		"appVersion":           app.Application_Version,
		"appUpdateLink":        app.Update_Link,
		"enableAppUpdates":     GetCheckValue(app.Update_Check),
		"enableIntegrityCheck": GetCheckValue(app.Integrity_Check),
		"enableAntiVPN":        GetCheckValue(app.AntiVPN),
		"antiVPNCheckbox":      checkBoxAntiVPNEnabled,
		"pauseApplication":     GetAppStatus(app.Status),
		"csrf":                 csrf,
	})

}

// REQUIRES AUTH
func HandleAppLicenses(c *gin.Context) {
	//csrf
	csrf := GetToken(c)
	// Check for active session, if doesn't exist force user to login
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	secret := c.Param("secret")

	app, err := GetApplication(currentUser, secret)
	if err != nil {
		panic(err)
	}

	if (Application{} == app) { // app doesn't exist or isnt owned by user
		c.Redirect(http.StatusPermanentRedirect, "/panel/dashboard")
		return
	}

	licenses, err := GetLicenses(app.Secret)
	if err != nil {
		panic(err)
	}

	c.HTML(http.StatusOK, "licenses.html", gin.H{
		"title":      settings.SiteName,
		"first":      settings.SiteNameFirst,
		"last":       settings.SiteNameLast,
		"appName":    app.Name,
		"username":   currentUser.Username,
		"Secret":     secret,
		"Licenses":   licenses,
		"MsgOnError": "",
		"csrf":       csrf,
	})

}

func HandleManageAppBlacklists(c *gin.Context) {
	csrf := GetToken(c)

	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	secret := c.PostForm("secret")

	app, err := GetApplication(currentUser, secret)
	if err != nil {
		panic(err)
	}

	if (Application{} == app) { // app doesn't exist or isnt owned by user
		c.Redirect(http.StatusPermanentRedirect, "/panel/dashboard")
		return
	}

	action := c.PostForm("action")

	switch action {
	case "remove":
		id := c.PostForm("id")

		err = RemoveBlacklist(app, id)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/blacklists")
	case "remove-all":
		err = RemoveAllBlacklists(app)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/blacklists")
	case "create":
		blacklistContent := c.PostForm("blacklistContent")
		blacklistType := c.PostForm("blacklistType")

		// check if premium user or not
		// if not user is allowed to create only a certain blacklist limit
		if currentUser.Active_Plan == "free" {

			blacklists, err := GetBlacklists(app.Secret)
			if err != nil {
				panic(err)
			}

			if len(blacklists) >= user_application_blacklist_limit {
				c.HTML(http.StatusOK, "blacklist.html", gin.H{
					"title":      settings.SiteName,
					"first":      settings.SiteNameFirst,
					"last":       settings.SiteNameLast,
					"appName":    app.Name,
					"username":   currentUser.Username,
					"Secret":     secret,
					"Blacklists": blacklists,
					"MsgOnError": "create_limit",
					"csrf":       csrf,
				})
				return
			}
		}

		err = AddBlacklistToApp(app.Secret, blacklistContent, blacklistType)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/blacklists")
	default:
		c.Redirect(http.StatusFound, "/panel/dashboard/app/"+app.Secret+"/blacklists")
	}
}

func HandleAppBlacklists(c *gin.Context) {
	// csrf
	csrf := GetToken(c)
	// Check for active session, if doesn't exist force user to login
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	secret := c.Param("secret")

	app, err := GetApplication(currentUser, secret)
	if err != nil {
		panic(err)
	}

	if (Application{} == app) { // app doesn't exist or isnt owned by user
		c.Redirect(http.StatusPermanentRedirect, "/panel/dashboard")
		return
	}

	blacklists, err := GetBlacklists(app.Secret)
	if err != nil {
		panic(err)
	}

	c.HTML(http.StatusOK, "blacklist.html", gin.H{
		"title":      settings.SiteName,
		"first":      settings.SiteNameFirst,
		"last":       settings.SiteNameLast,
		"appName":    app.Name,
		"username":   currentUser.Username,
		"Secret":     secret,
		"Blacklists": blacklists,
		"csrf":       csrf,
	})
}

func HandleAppVariables(c *gin.Context) {
	// csrf
	csrf := GetToken(c)
	// Check for active session, if doesn't exist force user to login
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	secret := c.Param("secret")

	app, err := GetApplication(currentUser, secret)
	if err != nil {
		panic(err)
	}

	if (Application{} == app) { // app doesn't exist or isnt owned by user
		c.Redirect(http.StatusPermanentRedirect, "/panel/dashboard")
		return
	}

	variables, err := GetVariables(app.Secret)
	if err != nil {
		panic(err)
	}

	c.HTML(http.StatusOK, "variables.html", gin.H{
		"title":     settings.SiteName,
		"first":     settings.SiteNameFirst,
		"last":      settings.SiteNameLast,
		"appName":   app.Name,
		"username":  currentUser.Username,
		"Secret":    secret,
		"Variables": variables,
		"csrf":      csrf,
	})
}

func HandleAppUsers(c *gin.Context) {
	// csrf
	csrf := GetToken(c)
	// Check for active session, if doesn't exist force user to login
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	secret := c.Param("secret")

	app, err := GetApplication(currentUser, secret)
	if err != nil {
		panic(err)
	}

	if (Application{} == app) { // app doesn't exist or isnt owned by user
		c.Redirect(http.StatusPermanentRedirect, "/panel/dashboard")
		return
	}

	users, err := GetUsers(app.Secret)
	if err != nil {
		panic(err)
	}

	c.HTML(http.StatusOK, "users.html", gin.H{
		"title":      settings.SiteName,
		"first":      settings.SiteNameFirst,
		"last":       settings.SiteNameLast,
		"appName":    app.Name,
		"username":   currentUser.Username,
		"Secret":     secret,
		"Users":      users,
		"userColor":  "",
		"MsgOnError": "",
		"csrf":       csrf,
	})
}

// REQUIRES AUTH
func HandleAppOverview(c *gin.Context) {
	// csrf
	csrf := GetToken(c)
	// Check for active session, if doesn't exist force user to login
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	secret := c.Param("secret")

	app, err := GetApplication(currentUser, secret)
	if err != nil {
		panic(err)
	}

	if (Application{} == app) { // app doesn't exist or isnt owned by user
		c.Redirect(http.StatusFound, "/panel/dashboard")
		return
	}

	totalLicenseCountUnused, err := GetTotalLicenseCountApplication(app, "no")
	if err != nil {
		panic(err)
	}

	totalLicenseCountUsed, err := GetTotalLicenseCountApplication(app, "yes")
	if err != nil {
		panic(err)
	}

	totalUserCount, err := GetTotalUserCountApplication(app)
	if err != nil {
		panic(err)
	}

	totalLogCount, err := GetTotalLogApplicationCount(app)
	if err != nil {
		panic(err)
	}

	totalBlacklistCount, err := GetTotalBlackListCountApplication(app)
	if err != nil {
		panic(err)
	}

	totalVariableCount, err := GetTotalVariableCountApplication(app)
	if err != nil {
		panic(err)
	}

	var errorMsg string
	if app.Status == "locked" {
		errorMsg = "app_locked"
	}

	c.HTML(http.StatusOK, "edit.html", gin.H{
		"title":               settings.SiteName,
		"first":               settings.SiteNameFirst,
		"last":                settings.SiteNameLast,
		"appName":             app.Name,
		"username":            currentUser.Username,
		"userAmount":          totalUserCount,
		"totalLicensesUnused": totalLicenseCountUnused,
		"totalLicensesUsed":   totalLicenseCountUsed,
		"totalLogs":           totalLogCount,
		"totalBlacklists":     totalBlacklistCount,
		"totalVariables":      totalVariableCount,
		"Secret":              secret,
		"MsgOnError":          errorMsg,
		"csrf":                csrf,
	})

}

// REQUIRES AUTH
func HandleUpgradeAccount(c *gin.Context) {
	// Check for active session, if doesn't exist force user to login
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	var buttonFree, buttonPremium, buttonEnterprise string

	if currentUser.Active_Plan == "free" {
		buttonFree = "CURRENT"
		buttonPremium = "Choose Professional"
		buttonEnterprise = "Contact Us"
	} else if currentUser.Active_Plan == "professional" {
		buttonFree = "DISABLED"
		buttonPremium = "CURRENT"
		buttonEnterprise = "Contact Us"
	} else if currentUser.Active_Plan == "enterprise" {
		buttonFree = "DISABLED"
		buttonPremium = "DISABLED"
		buttonEnterprise = "CURRENT"
	}

	payments, err := GetPayments(currentUser.ID)
	if err != nil {
		panic(err)
	}

	c.HTML(http.StatusOK, "upgrade_account.html", gin.H{
		"title":              settings.SiteName,
		"first":              settings.SiteNameFirst,
		"last":               settings.SiteNameLast,
		"username":           currentUser.Username,
		"userid":             currentUser.ID,
		"buttonFree":         buttonFree,
		"buttonProfessional": buttonPremium,
		"buttonEnterprise":   buttonEnterprise,
		"Payments":           payments,
	})
}

// REQUIRES AUTH

func HandleAccount2FA(c *gin.Context) {
	// Check for active session, if doesn't exist force user to login
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	userVerification, err := GetUserVerificationData(currentUser.Username)
	if err != nil {
		panic(err)
	}

	action := c.Param("action")

	switch action {
	case "/enable":
		// generate key

		secureKey := GenerateSecretKey()
		qrCodeRaw := GenerateQRCode(settings.SiteName, secureKey)

		err = Add2FACodeToUser(userVerification, secureKey, qrCodeRaw)
		if err != nil {
			panic(err)
		}
		c.Redirect(http.StatusFound, "/panel/account")
	case "/disable":
		err := Remove2FACodeFromUser(userVerification)
		if err != nil {
			panic(err)
		}

		c.Redirect(http.StatusFound, "/panel/account")
	default:
		c.Redirect(http.StatusFound, "/panel/account")
	}

}

func HandleAccountVerify(c *gin.Context) {
	csrf := GetToken(c)
	// Check for active session, if doesn't exist force user to login
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	userVerification, err := GetUserVerificationData(currentUser.Username)
	if err != nil {
		panic(err)
	}

	var button2FAText, action2FA string
	if userVerification.Enabled2FA == 1 {
		button2FAText = "Disable"
		action2FA = "disable-2fa"
	} else {
		button2FAText = "Enable"
		action2FA = "enable-2fa"
	}

	var isVerified, colorVerifiedStatus string

	verified := currentUser.IsVerified
	if verified == 0 {
		isVerified = "NO"
		colorVerifiedStatus = settings.ErrorColor
	} else {
		isVerified = "YES"
		colorVerifiedStatus = settings.GreenColor
	}

	if verified == 1 {
		c.HTML(http.StatusOK, "account.html", gin.H{
			"title":               settings.SiteName,
			"first":               settings.SiteNameFirst,
			"last":                settings.SiteNameLast,
			"username":            currentUser.Username,
			"userid":              currentUser.ID,
			"user_email":          currentUser.Email,
			"user_role":           currentUser.Group,
			"user_active_plan":    currentUser.Active_Plan,
			"user_sub_exp":        currentUser.SubExp,
			"MsgOnError":          "alreadyVerified",
			"verified":            isVerified,
			"colorVerifiedStatus": colorVerifiedStatus,
			"Action2FA":           action2FA,
			"ButtonText2FA":       button2FAText,
			"QRCode":              userVerification.QRCode,
			"csrf":                csrf,
		})
		return
	}

	// check if expired
	expired := UserExpired(userVerification.Timeout, GetCurrentTime())
	if !expired {
		c.HTML(http.StatusBadRequest, "account.html", gin.H{
			"title":               settings.SiteName,
			"first":               settings.SiteNameFirst,
			"last":                settings.SiteNameLast,
			"username":            currentUser.Username,
			"userid":              currentUser.ID,
			"user_email":          currentUser.Email,
			"user_role":           currentUser.Group,
			"user_active_plan":    currentUser.Active_Plan,
			"user_sub_exp":        currentUser.SubExp,
			"MsgOnError":          "requestLimit",
			"verified":            isVerified,
			"colorVerifiedStatus": colorVerifiedStatus,
			"Action2FA":           action2FA,
			"ButtonText2FA":       button2FAText,
			"QRCode":              userVerification.QRCode,
			"csrf":                csrf,
		})
		return
	}

	// Email was found prepare everything else
	emailVerficationCode := RandomString(64)
	emailCodeHashed, err := HashPassword(emailVerficationCode)
	if err != nil {
		panic(err)
	}

	err = UpdateVerificationHashForEmail(emailCodeHashed, currentUser.Email)
	if err != nil {
		c.HTML(http.StatusBadRequest, "account.html", gin.H{
			"title":               settings.SiteName,
			"first":               settings.SiteNameFirst,
			"last":                settings.SiteNameLast,
			"username":            currentUser.Username,
			"userid":              currentUser.ID,
			"user_email":          currentUser.Email,
			"user_role":           currentUser.Group,
			"user_active_plan":    currentUser.Active_Plan,
			"user_sub_exp":        currentUser.SubExp,
			"MsgOnError":          "failed",
			"verified":            isVerified,
			"colorVerifiedStatus": colorVerifiedStatus,
			"Action2FA":           action2FA,
			"ButtonText2FA":       button2FAText,
			"QRCode":              userVerification.QRCode,
			"csrf":                csrf,
		})
		return
	}

	SendEmail(currentUser.Username, currentUser.Email, emailVerficationCode)

	c.HTML(http.StatusOK, "account.html", gin.H{
		"title":               settings.SiteName,
		"first":               settings.SiteNameFirst,
		"last":                settings.SiteNameLast,
		"username":            currentUser.Username,
		"userid":              currentUser.ID,
		"user_email":          currentUser.Email,
		"user_role":           currentUser.Group,
		"user_active_plan":    currentUser.Active_Plan,
		"user_sub_exp":        currentUser.SubExp,
		"MsgOnError":          "linkSent",
		"verified":            isVerified,
		"colorVerifiedStatus": colorVerifiedStatus,
		"Action2FA":           action2FA,
		"ButtonText2FA":       button2FAText,
		"QRCode":              userVerification.QRCode,
		"csrf":                csrf,
	})
}

// REQUIRES AUTH
func HandleAccount(c *gin.Context) {
	csrf := GetToken(c)
	// Check for active session, if doesn't exist force user to login
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	userVerification, err := GetUserVerificationData(currentUser.Username)
	if err != nil {
		panic(err)
	}

	var button2FAText, action2FA string
	if userVerification.Enabled2FA == 1 {
		button2FAText = "Disable"
		action2FA = "disable"
	} else {
		button2FAText = "Enable"
		action2FA = "enable"
	}

	var msgVerify, isVerified, colorVerifiedStatus string

	verified := currentUser.IsVerified
	if verified == 0 {
		msgVerify = "requireVerify"
		isVerified = "NO"
		colorVerifiedStatus = settings.ErrorColor
	} else {
		msgVerify = ""
		isVerified = "YES"
		colorVerifiedStatus = settings.GreenColor
	}

	c.HTML(http.StatusOK, "account.html", gin.H{
		"title":               settings.SiteName,
		"first":               settings.SiteNameFirst,
		"last":                settings.SiteNameLast,
		"username":            currentUser.Username,
		"userid":              currentUser.ID,
		"user_email":          currentUser.Email,
		"user_role":           currentUser.Group,
		"user_active_plan":    currentUser.Active_Plan,
		"user_sub_exp":        currentUser.SubExp,
		"MsgOnError":          msgVerify,
		"verified":            isVerified,
		"colorVerifiedStatus": colorVerifiedStatus,
		"Action2FA":           action2FA,
		"ButtonText2FA":       button2FAText,
		"QRCode":              userVerification.QRCode,
		"csrf":                csrf,
	})
}

// REQUIRES AUTH
func HandleLogs(c *gin.Context) {
	// Check for active session, if doesn't exist force user to login
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	loginHistory, err := GetAllLoginHistorys(currentUser)
	if err != nil {
		panic(err)
	}

	c.HTML(http.StatusOK, "logs.html", gin.H{
		"title":        settings.SiteName,
		"first":        settings.SiteNameFirst,
		"last":         settings.SiteNameLast,
		"username":     currentUser.Username,
		"LoginHistory": loginHistory,
	})

}

func HandleDashboardUpdateKeyPair(c *gin.Context) {
	// Check for active session, if doesn't exist force user to login
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	secret := c.PostForm("secret")

	err = UpdateApplicationKeyPair(secret)
	if err != nil {
		panic(err)
	}

	c.Redirect(http.StatusFound, "/panel/dashboard")
}

func HandleDashboardUpdateSecret(c *gin.Context) {
	// Check for active session, if doesn't exist force user to login
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	secret := c.PostForm("secret")

	err = UpdateApplicationSecret(secret)
	if err != nil {
		panic(err)
	}

	c.Redirect(http.StatusFound, "/panel/dashboard")
}

func HandleDashboardRemoveApp(c *gin.Context) {
	// Check for active session, if doesn't exist force user to login
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	secret := c.PostForm("secret")

	err = RemoveApplication(currentUser, secret)
	if err != nil {
		panic(err)
	}
	c.Redirect(http.StatusFound, "/panel/dashboard")
}

func HandleDashboardUpdateAppName(c *gin.Context) {
	// Get CSRF
	csrf := GetToken(c)

	// Check for active session, if doesn't exist force user to login
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	secret := c.PostForm("secret")
	newAppName := c.PostForm("applicationName")

	if containsForbiddenCharacters(newAppName) {
		currentApp, err := GetApplication(currentUser, secret)
		if err != nil {
			panic(err)
		}

		totalLicenseCountUnused, err := GetTotalLicenseCountApplication(currentApp, "no")
		if err != nil {
			panic(err)
		}

		totalLicenseCountUsed, err := GetTotalLicenseCountApplication(currentApp, "yes")
		if err != nil {
			panic(err)
		}

		totalUserCount, err := GetTotalUserCountApplication(currentApp)
		if err != nil {
			panic(err)
		}

		totalLogCount, err := GetTotalLogApplicationCount(currentApp)
		if err != nil {
			panic(err)
		}

		totalBlacklistCount, err := GetTotalBlackListCountApplication(currentApp)
		if err != nil {
			panic(err)
		}

		totalVariableCount, err := GetTotalVariableCountApplication(currentApp)
		if err != nil {
			panic(err)
		}

		c.HTML(http.StatusOK, "edit.html", gin.H{
			"title":               settings.SiteName,
			"first":               settings.SiteNameFirst,
			"last":                settings.SiteNameLast,
			"appName":             currentApp.Name,
			"username":            currentUser.Username,
			"userAmount":          totalUserCount,
			"totalLicensesUnused": totalLicenseCountUnused,
			"totalLicensesUsed":   totalLicenseCountUsed,
			"totalLogs":           totalLogCount,
			"totalBlacklists":     totalBlacklistCount,
			"totalVariables":      totalVariableCount,
			"Secret":              secret,
			"MsgOnError":          "invalid_format",
			"color":               settings.YellowColor,
			"csrf":                csrf,
		})
		return
	}

	appExists, err := AppAlreadyExists(newAppName)
	if err != nil {
		panic(err)
	}

	if appExists {

		currentApp, err := GetApplication(currentUser, secret)
		if err != nil {
			panic(err)
		}

		totalLicenseCountUnused, err := GetTotalLicenseCountApplication(currentApp, "no")
		if err != nil {
			panic(err)
		}

		totalLicenseCountUsed, err := GetTotalLicenseCountApplication(currentApp, "yes")
		if err != nil {
			panic(err)
		}

		totalUserCount, err := GetTotalUserCountApplication(currentApp)
		if err != nil {
			panic(err)
		}

		totalLogCount, err := GetTotalLogApplicationCount(currentApp)
		if err != nil {
			panic(err)
		}

		totalBlacklistCount, err := GetTotalBlackListCountApplication(currentApp)
		if err != nil {
			panic(err)
		}

		totalVariableCount, err := GetTotalVariableCountApplication(currentApp)
		if err != nil {
			panic(err)
		}

		c.HTML(http.StatusOK, "edit.html", gin.H{
			"title":               settings.SiteName,
			"first":               settings.SiteNameFirst,
			"last":                settings.SiteNameLast,
			"appName":             currentApp.Name,
			"username":            currentUser.Username,
			"userAmount":          totalUserCount,
			"totalLicensesUnused": totalLicenseCountUnused,
			"totalLicensesUsed":   totalLicenseCountUsed,
			"totalLogs":           totalLogCount,
			"totalBlacklists":     totalBlacklistCount,
			"totalVariables":      totalVariableCount,
			"Secret":              secret,
			"MsgOnError":          "app_exists",
			"color":               settings.YellowColor,
			"csrf":                csrf,
		})
		return
	}

	err = UpdateApplicationName(secret, newAppName)
	if err != nil {
		panic(err)
	}

	c.Redirect(http.StatusFound, "/panel/dashboard/app/"+secret)
}

func HandleDashboardCreateNewApp(c *gin.Context) {
	// csrf
	csrf := GetToken(c)
	// Check for active session, if doesn't exist force user to login
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	appName := c.PostForm("applicationName")

	if containsForbiddenCharacters(appName) {
		// get user applications
		applications, err := GetApplications(currentUser.ID)
		if err != nil {
			panic(err)
		}

		totalLicenses, err := GetTotalLicenses(applications)
		if err != nil {
			panic(err)
		}

		totalUserCount, err := GetTotalUsers(applications)
		if err != nil {
			panic(err)
		}

		c.HTML(http.StatusOK, "dashboard.html", gin.H{
			"title":             settings.SiteName,
			"first":             settings.SiteNameFirst,
			"last":              settings.SiteNameLast,
			"username":          currentUser.Username,
			"MsgOnError":        "invalid_format",
			"color":             settings.ErrorColor,
			"Applications":      applications,
			"applicationAmount": len(applications),
			"totalLicenses":     totalLicenses,
			"totalUsers":        totalUserCount,
			"csrf":              csrf,
		})
		return
	}

	appExists, err := AppAlreadyExists(appName)
	if err != nil {
		panic(err)
	}

	if appExists {

		// get user applications
		applications, err := GetApplications(currentUser.ID)
		if err != nil {
			panic(err)
		}

		totalLicenses, err := GetTotalLicenses(applications)
		if err != nil {
			panic(err)
		}

		totalUserCount, err := GetTotalUsers(applications)
		if err != nil {
			panic(err)
		}

		c.HTML(http.StatusOK, "dashboard.html", gin.H{
			"title":             settings.SiteName,
			"first":             settings.SiteNameFirst,
			"last":              settings.SiteNameLast,
			"username":          currentUser.Username,
			"MsgOnError":        "app_exists",
			"color":             settings.YellowColor,
			"Applications":      applications,
			"applicationAmount": len(applications),
			"totalLicenses":     totalLicenses,
			"totalUsers":        totalUserCount,
			"csrf":              csrf,
		})
		return
	}

	// check if premium user or not
	// if not user is allowed to create only 1 application
	if currentUser.Active_Plan == "free" {

		// get user applications
		applications, err := GetApplications(currentUser.ID)
		if err != nil {
			panic(err)
		}

		totalLicenses, err := GetTotalLicenses(applications)
		if err != nil {
			panic(err)
		}

		totalUserCount, err := GetTotalUsers(applications)
		if err != nil {
			panic(err)
		}

		if len(applications) >= user_application_limit {
			c.HTML(http.StatusOK, "dashboard.html", gin.H{
				"title":             settings.SiteName,
				"first":             settings.SiteNameFirst,
				"last":              settings.SiteNameLast,
				"username":          currentUser.Username,
				"MsgOnError":        "app_limit_reached",
				"color":             settings.ErrorColor,
				"Applications":      applications,
				"applicationAmount": len(applications),
				"totalLicenses":     totalLicenses,
				"totalUsers":        totalUserCount,
				"csrf":              csrf,
			})
			return
		}
	}

	err = AddNewApplication(currentUser, appName)
	if err != nil {

		// get user applications
		applications, err := GetApplications(currentUser.ID)
		if err != nil {
			panic(err)
		}

		totalLicenses, err := GetTotalLicenses(applications)
		if err != nil {
			panic(err)
		}

		totalUserCount, err := GetTotalUsers(applications)
		if err != nil {
			panic(err)
		}

		c.HTML(http.StatusOK, "dashboard.html", gin.H{
			"title":             settings.SiteName,
			"first":             settings.SiteNameFirst,
			"last":              settings.SiteNameLast,
			"username":          currentUser.Username,
			"MsgOnError":        "app_create_failed",
			"color":             settings.ErrorColor,
			"Applications":      applications,
			"applicationAmount": len(applications),
			"totalLicenses":     totalLicenses,
			"totalUsers":        totalUserCount,
			"csrf":              csrf,
		})
		return
	}

	applications, err := GetApplications(currentUser.ID)
	if err != nil {
		panic(err)
	}

	totalLicenses, err := GetTotalLicenses(applications)
	if err != nil {
		panic(err)
	}

	totalUserCount, err := GetTotalUsers(applications)
	if err != nil {
		panic(err)
	}

	c.HTML(302, "dashboard.html", gin.H{
		"title":             settings.SiteName,
		"first":             settings.SiteNameFirst,
		"last":              settings.SiteNameLast,
		"username":          currentUser.Username,
		"MsgOnError":        "app_created",
		"color":             settings.GreenColor,
		"Applications":      applications,
		"applicationAmount": len(applications),
		"totalLicenses":     totalLicenses,
		"totalUsers":        totalUserCount,
		"csrf":              csrf,
	})
}

// REQUIRES AUTH
func HandleDashboard(c *gin.Context) {
	csrf := GetToken(c)
	// Check for active session, if doesn't exist force user to login
	session := sessions.Default(c)
	sessionName := session.Get(settings.SessionName)

	if !IsAuthenticated(session) {
		c.Redirect(http.StatusPermanentRedirect, "/sign-in")
		return
	}

	currentUser, err := GetUserData(sessionName.(string))
	if err != nil {
		panic(err)
	}

	if !IsEmailVerified(currentUser) {
		c.Redirect(http.StatusPermanentRedirect, "/panel/account")
	}

	UpdateSubscriptionStatus(currentUser) // Updates subscripton accordingly

	// get user applications
	applications, err := GetApplications(currentUser.ID)
	if err != nil {
		panic(err)
	}

	// total license count
	totalLicenseCount, err := GetTotalLicenseCount(currentUser)
	if err != nil {
		panic(err)
	}

	// total user count
	totalUserCount, err := GetTotalUsers(applications)
	if err != nil {
		panic(err)
	}

	// total log count
	totalLogCount, err := GetTotalLogCount(currentUser)
	if err != nil {
		panic(err)
	}

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"title":             settings.SiteName,
		"first":             settings.SiteNameFirst,
		"last":              settings.SiteNameLast,
		"username":          currentUser.Username,
		"Applications":      applications,
		"applicationAmount": len(applications),
		"totalLicenses":     totalLicenseCount,
		"totalUsers":        totalUserCount,
		"totalLogs":         totalLogCount,
		"MsgOnError":        "",
		"csrf":              csrf,
	})
}

func HandleRecovery(c *gin.Context) {
	csrf := GetToken(c)

	c.HTML(http.StatusOK, "recovery.html", gin.H{
		"title": settings.SiteName,
		"first": settings.SiteNameFirst,
		"last":  settings.SiteNameLast,
		"csrf":  csrf,
	})
}

func AccountPasswordChangeHandler(c *gin.Context) {
	csrf := GetToken(c)

	var u User_Verification
	username := c.PostForm("username")
	verificationCode := c.PostForm("pass")

	u, err := GetUserVerificationData(username)
	if err != nil {
		c.HTML(http.StatusBadRequest, "changepwd.html", gin.H{
			"title":      settings.SiteName,
			"first":      settings.SiteNameFirst,
			"last":       settings.SiteNameLast,
			"MsgOnError": "invalid",
			"color":      settings.ErrorColor,
			"username":   username,
			"pass":       verificationCode,
			"csrf":       csrf,
		})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(u.Code), []byte(verificationCode))
	if err != nil {
		c.HTML(http.StatusBadRequest, "changepwd.html", gin.H{
			"title":      settings.SiteName,
			"first":      settings.SiteNameFirst,
			"last":       settings.SiteNameLast,
			"MsgOnError": "invalid",
			"color":      settings.ErrorColor,
			"username":   username,
			"pass":       verificationCode,
			"csrf":       csrf,
		})
		return
	}
	passwordOne := c.PostForm("passwordOne")
	passwordTwo := c.PostForm("passwordTwo")

	err = checkPasswordCriteria(passwordOne)
	if err != nil {
		c.HTML(http.StatusBadRequest, "changepwd.html", gin.H{
			"title":      settings.SiteName,
			"first":      settings.SiteNameFirst,
			"last":       settings.SiteNameLast,
			"MsgOnError": "invalidPassword",
			"color":      settings.ErrorColor,
			"username":   username,
			"pass":       verificationCode,
			"csrf":       csrf,
		})
		return
	}

	if passwordOne != passwordTwo {
		c.HTML(http.StatusBadRequest, "changepwd.html", gin.H{
			"title":      settings.SiteName,
			"first":      settings.SiteNameFirst,
			"last":       settings.SiteNameLast,
			"MsgOnError": "passwordMatchError",
			"color":      settings.ErrorColor,
			"username":   username,
			"pass":       verificationCode,
			"csrf":       csrf,
		})
		return
	}

	newPassHash, err := HashPassword(passwordOne)
	if err != nil {
		c.HTML(http.StatusBadRequest, "changepwd.html", gin.H{
			"title":      settings.SiteName,
			"first":      settings.SiteNameFirst,
			"last":       settings.SiteNameLast,
			"MsgOnError": "invalid",
			"color":      settings.ErrorColor,
			"username":   username,
			"pass":       verificationCode,
			"csrf":       csrf,
		})
		return
	}

	err = UpdatePasswordHash(u, newPassHash)
	if err != nil {
		c.HTML(http.StatusBadRequest, "changepwd.html", gin.H{
			"title":    settings.SiteName,
			"first":    settings.SiteNameFirst,
			"last":     settings.SiteNameLast,
			"msg":      "invalid",
			"color":    settings.ErrorColor,
			"username": username,
			"pass":     verificationCode,
			"csrf":     csrf,
		})
		return
	}

	c.HTML(http.StatusOK, "login.html", gin.H{
		"title":      settings.SiteName,
		"first":      settings.SiteNameFirst,
		"last":       settings.SiteNameLast,
		"MsgOnError": "passChanged",
		"color":      settings.GreenColor,
		"csrf":       csrf,
	})
}

func AccountRecoveryHandler(c *gin.Context) {
	csrf := GetToken(c)

	var u User_Verification
	username := c.Param("username")
	verificationCode := c.Param("pass")

	u, err := GetUserVerificationData(username)
	if err != nil {
		panic(err)
	}
	// check if time expired

	expired := UserExpired(u.Timeout_Pass, GetCurrentTime())
	if expired {
		c.HTML(http.StatusOK, "changepwd.html", gin.H{
			"title":      settings.SiteName,
			"first":      settings.SiteNameFirst,
			"last":       settings.SiteNameLast,
			"MsgOnError": "linkExpired",
			"csrf":       csrf,
			"color":      settings.ErrorColor,
		})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(u.Code), []byte(verificationCode))
	if err != nil {
		c.HTML(http.StatusOK, "changepwd.html", gin.H{
			"title":      settings.SiteName,
			"first":      settings.SiteNameFirst,
			"last":       settings.SiteNameLast,
			"MsgOnError": "invalidCode",
			"csrf":       csrf,
			"color":      settings.ErrorColor,
		})
		return
	}

	c.HTML(http.StatusOK, "changepwd.html", gin.H{
		"title":      settings.SiteName,
		"first":      settings.SiteNameFirst,
		"last":       settings.SiteNameLast,
		"csrf":       csrf,
		"MsgOnError": "",
		"color":      settings.ErrorColor,
		"username":   username,
		"pass":       verificationCode,
	})
}

func HandlePwdRecovery(c *gin.Context) {
	csrf := GetToken(c)

	email := c.Request.FormValue("email")

	var u User
	u, err := GetUserByEmail(email)
	if err != nil {
		panic(err)
	}

	var u_ver User_Verification
	u_ver, err = GetUserVerificationData(u.Username)
	if err != nil {
		panic(err)
	}

	expired := UserExpired(u_ver.Timeout_Pass, GetCurrentTime())
	if !expired {
		c.HTML(http.StatusBadRequest, "recovery.html", gin.H{
			"title":      settings.SiteName,
			"first":      settings.SiteNameFirst,
			"last":       settings.SiteNameLast,
			"MsgOnError": "requestLimit",
			"color":      settings.ErrorColor,
			"csrf":       csrf,
		})
		return
	}

	if email != u.Email {
		c.HTML(http.StatusBadRequest, "recovery.html", gin.H{
			"title":      settings.SiteName,
			"first":      settings.SiteNameFirst,
			"last":       settings.SiteNameLast,
			"MsgOnError": "invalid",
			"color":      settings.ErrorColor,
			"csrf":       csrf,
		})
		return
	}

	// Email was found prepare everything else
	emailVerficationCode := RandomString(64)
	emailCodeHashed, err := HashPassword(emailVerficationCode)
	if err != nil {
		panic(err)
	}

	err = UpdateVerificationHashForEmail(emailCodeHashed, email)
	if err != nil {
		c.HTML(http.StatusBadRequest, "recovery.html", gin.H{
			"title":      settings.SiteName,
			"first":      settings.SiteNameFirst,
			"last":       settings.SiteNameLast,
			"MsgOnError": "invalid",
			"color":      settings.ErrorColor,
			"csrf":       csrf,
		})
		return
	}

	SendRecoveryEmail(email, u.Username, emailVerficationCode)

	c.HTML(http.StatusBadRequest, "recovery.html", gin.H{
		"title":      settings.SiteName,
		"first":      settings.SiteNameFirst,
		"last":       settings.SiteNameLast,
		"MsgOnError": "emailSent",
		"color":      settings.GreenColor,
		"csrf":       csrf,
	})
}

func HandleSignUp(c *gin.Context) {

	csrf := GetToken(c)

	email := c.Request.FormValue("email")
	username := c.Request.FormValue("username")
	pass := c.Request.FormValue("pass")
	passrepeat := c.Request.FormValue("passrepeat")

	allowed := true

	if checkEmailCriteria(email) != nil {
		allowed = false
	}

	if !allowed {
		c.HTML(http.StatusUnauthorized, "register.html", gin.H{
			"title":      settings.SiteName,
			"first":      settings.SiteNameFirst,
			"last":       settings.SiteNameLast,
			"MsgOnError": "emailForbidden",
			"color":      settings.ErrorColor,
			"boxheight":  "670px",
			"csrf":       csrf,
		})
		return
	}

	if checkUsernameCriteria(username) != nil {
		c.HTML(http.StatusUnauthorized, "register.html", gin.H{
			"title":      settings.SiteName,
			"first":      settings.SiteNameFirst,
			"last":       settings.SiteNameLast,
			"MsgOnError": "usernameForbidden",
			"color":      settings.ErrorColor,
			"boxheight":  "720px",
			"csrf":       csrf,
		})
		return
	}

	if checkPasswordCriteria(pass) != nil {
		c.HTML(http.StatusUnauthorized, "register.html", gin.H{
			"title":      settings.SiteName,
			"first":      settings.SiteNameFirst,
			"last":       settings.SiteNameLast,
			"MsgOnError": "passwordForbidden",
			"color":      settings.ErrorColor,
			"boxheight":  "740px",
			"csrf":       csrf,
		})
		return
	}

	if !RegisterPassSame(pass, passrepeat) {
		c.HTML(http.StatusUnauthorized, "register.html", gin.H{
			"title":      settings.SiteName,
			"first":      settings.SiteNameFirst,
			"last":       settings.SiteNameLast,
			"MsgOnError": "passwordMatchError",
			"color":      settings.ErrorColor,
			"boxheight":  "670px",
			"csrf":       csrf,
		})
		return
	}

	exists, err := UserExists(username)

	if err != nil {
		panic(err)
	}

	if exists {
		c.HTML(http.StatusUnauthorized, "register.html", gin.H{
			"title":      settings.SiteName,
			"first":      settings.SiteNameFirst,
			"last":       settings.SiteNameLast,
			"MsgOnError": "usernameTaken",
			"color":      settings.ErrorColor,
			"boxheight":  "670px",
			"csrf":       csrf,
		})
		return
	}

	taken, err := EmailTaken(email)
	if err != nil {
		panic(err)
	}

	if taken {
		c.HTML(http.StatusUnauthorized, "register.html", gin.H{
			"title":      settings.SiteName,
			"first":      settings.SiteNameFirst,
			"last":       settings.SiteNameLast,
			"MsgOnError": "emailTaken",
			"color":      settings.ErrorColor,
			"boxheight":  "670px",
			"csrf":       csrf,
		})
		return
	}

	err = AddNewUser(email, username, pass, c.ClientIP())
	if err != nil {
		c.HTML(http.StatusUnauthorized, "register.html", gin.H{
			"title":      settings.SiteName,
			"first":      settings.SiteNameFirst,
			"last":       settings.SiteNameLast,
			"MsgOnError": "serverError",
			"color":      settings.ErrorColor,
			"boxheight":  "670px",
			"csrf":       csrf,
		})
		return
	}

	c.HTML(http.StatusUnauthorized, "register.html", gin.H{
		"title":      settings.SiteName,
		"first":      settings.SiteNameFirst,
		"last":       settings.SiteNameLast,
		"MsgOnError": "accountCreated",
		"color":      settings.GreenColor,
		"boxheight":  "670px",
		"csrf":       csrf,
	})

}

func HandleSignIn(c *gin.Context) {

	csrf := GetToken(c)

	session := sessions.Default(c)

	username := c.PostForm("username")
	password := c.PostForm("password")
	code := c.PostForm("code")

	if checkUsernameCriteria(username) != nil {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"title":      settings.SiteName,
			"first":      settings.SiteNameFirst,
			"last":       settings.SiteNameLast,
			"MsgOnError": "invalidUsername",
			"color":      settings.ErrorColor,
			"csrf":       csrf,
		})
		return
	}

	exists, err := UserExists(username)
	if err != nil {
		panic(err)
	}

	if !exists {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"title":      settings.SiteName,
			"first":      settings.SiteNameFirst,
			"last":       settings.SiteNameLast,
			"MsgOnError": "accountInvalid",
			"color":      settings.ErrorColor,
			"csrf":       csrf,
		})
		return
	}

	user, err := GetUserData(username)
	if err != nil {
		panic(err)
	}

	userVerification, err := GetUserVerificationData(user.Username)
	if err != nil {
		panic(err)
	}

	if ComparePassword(user.Password, password) {
		// check for 2fa
		if userVerification.Enabled2FA == 1 {

			if code == "" {
				c.HTML(http.StatusOK, "auth2.html", gin.H{
					"title":      settings.SiteName,
					"first":      settings.SiteNameFirst,
					"last":       settings.SiteNameLast,
					"MsgOnError": "",
					"color":      settings.ErrorColor,
					"username":   username,
					"password":   password,
					"csrf":       csrf,
				})
				return
			}

			if !Verify2FACode(userVerification.Secret2FA, code) {
				c.HTML(http.StatusOK, "auth2.html", gin.H{
					"title":      settings.SiteName,
					"first":      settings.SiteNameFirst,
					"last":       settings.SiteNameLast,
					"MsgOnError": "invalid",
					"color":      settings.ErrorColor,
					"username":   username,
					"password":   password,
					"csrf":       csrf,
				})
				return
			}
		}
		session.Set(settings.SessionName, username)

		if err := session.Save(); err != nil {
			return
		}

		currentIP := c.ClientIP()
		browserInfo := c.GetHeader("User-Agent")

		err := AddLoginLog(currentIP, browserInfo, user)
		if err != nil {
			panic(err)
		}

		c.Redirect(http.StatusFound, "/panel/dashboard")
	} else {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"title":      settings.SiteName,
			"first":      settings.SiteNameFirst,
			"last":       settings.SiteNameLast,
			"MsgOnError": "invalidCredentials",
			"color":      settings.ErrorColor,
			"csrf":       csrf,
		})
		return
	}
}

func HandleVerify(c *gin.Context) {
	var u User_Verification
	username := c.Param("username")
	verificationCode := c.Param("pass")

	u, err := GetUserVerificationData(username)
	if err != nil {
		log.Fatal(err)
	}

	expired := UserExpired(u.Timeout, GetCurrentTime())
	if expired {
		c.HTML(http.StatusBadRequest, "activate.html", gin.H{
			"title": settings.SiteName,
			"first": settings.SiteNameFirst,
			"last":  settings.SiteNameLast,
			"msg":   "Verification link expired, please request a new one!",
			"color": settings.ErrorColor,
		})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(u.Code), []byte(verificationCode))
	if err == nil {
		// update user to active account
		err := ActivateUserAccount(u)

		if err != nil {
			c.HTML(http.StatusBadRequest, "activate.html", gin.H{
				"title": settings.SiteName,
				"first": settings.SiteNameFirst,
				"last":  settings.SiteNameLast,
				"msg":   "Please try to open email confirmation link again!",
				"color": settings.ErrorColor,
			})
			return
		}

		c.HTML(http.StatusOK, "activate.html", gin.H{
			"title": settings.SiteName,
			"first": settings.SiteNameFirst,
			"last":  settings.SiteNameLast,
			"msg":   "Account has been activated!",
			"color": settings.GreenColor,
		})
		return
	}

	c.HTML(http.StatusUnauthorized, "activate.html", gin.H{
		"title": settings.SiteName,
		"first": settings.SiteNameFirst,
		"last":  settings.SiteNameLast,
		"msg":   "Please try to open email confirmation link again!",
		"color": settings.ErrorColor,
	})

}
