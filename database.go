package main

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

type User struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Email        string `json:"email"`
	Active_Plan  string `json:"active_plan"`
	Group        string `json:"active_group"`
	IsVerified   int    `json:"is_verified"`
	CreatedAt    string `json:"createdAt"`
	RegisteredIP string `json:"ip_registered"`
	SubExp       string `json:"sub_exp"`
}

type User_Verification struct {
	Email        string `json:"email"`
	Username     string `json:"username"`
	Code         string `json:"code"`
	Timeout      string `json:"timeout"`
	Timeout_Pass string `json:"timeout_pass"`
	Enabled2FA   int    `json:"enabled2FA"`
	Secret2FA    string `json:"secret2FA"`
	QRCode       string `json:"qrcode"`
}

type UserLoginHistory struct {
	UserID  string `json:"userid"`
	Time    string `json:"time"`
	IP      string `json:"ip"`
	Browser string `json:"browser"`
}

type Application_User struct {
	App_Secret  string `json:"app_secret"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	IP          string `json:"ip"`
	Password    string `json:"password"`
	Exp_Date    string `json:"exp_date"`
	Expired     string `json:"expired"`
	HWID        string `json:"hwid"`
	Last_Login  string `json:"last_login"`
	Created_At  string `json:"created_at"`
	Banned      string `json:"banned"`
	Variable    string `json:"var"`
	Level       string `json:"level"`
	Color       string
	ColorBanned string
}

type Application_Log struct {
	App_Secret string `json:"app_secret"`
	LogID      string `json:"logid"`
	Time       string `json:"time"`
	Username   string `json:"username"`
	Action     string `json:"action"`
}

type Application struct {
	Name                string `json:"name"`
	Secret              string `json:"secret"`
	Pub_Key             string `json:"pub_key"`
	Priv_Key            string `json:"priv_key"`
	Status              string `json:"status"`
	Owner               string `json:"owner"`
	Integrity_Check     string `json:"int_check"`
	Application_Hash    string `json:"app_hash"`
	Application_Version string `json:"app_version"`
	Update_Check        string `json:"updt_check"`
	Update_Link         string `json:"update_link"`
	AntiVPN             string `json:"antivpn"`
	Color               string
}

type License struct {
	App_Secret string `json:"app_secret"`
	License    string `json:"license"`
	Exp        string `json:"exp"`
	Level      string `json:"level"`
	Used       string `json:"used"`
	Used_By    string `json:"used_by"`
	Color      string
}

type Payment struct {
	UserID     string `json:"userid"`
	PaymentID  string `json:"payment_id"`
	Created_At string `json:"created_at"`
	Gateway    string `json:"gateway"`
	Amount     string `json:"amount"`
	Status     string `json:"status"`
	Color      string
}

type Variable struct {
	App_Secret      string `json:"app_secret"`
	Variable_Secret string `json:"var_secret"`
	Variable_Name   string `json:"var_name"`
	Variable_Value  string `json:"var_value"`
}

type Blacklist struct {
	App_Secret     string `json:"app_secret"`
	ID             string `json:"id"`
	Blacklist_Type string `json:"type"`
	Blacklist_Data string `json:"data"`
}

var (
	DBConnect string
	DBType    = "mysql"
)

func InitDB() {
	DBConnect = settings.DBLogin + ":" + settings.DBPass + "@tcp(" + settings.DBConnection + ")/" + settings.DBName
}

//// SECTION FOR ADMIN PANEL ////

func TotalSubscriptionCountAuthSphere() (int64, error) {
	var totalCount int64

	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return totalCount, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return totalCount, err
	}

	var results *sql.Rows
	results, err = db.Query("SELECT count(*) as count_sub FROM users WHERE sub_exp NOT LIKE 'N/A'")
	if err != nil {
		return totalCount, err
	}

	var count_sub int64
	for results.Next() {
		err = results.Scan(&count_sub)
		if err != nil {
			return totalCount, err
		}
		totalCount += count_sub
	}
	return totalCount, nil
}

func TotalUserCountRegisteredAuthSphere() (int64, error) {
	var totalCount int64

	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return totalCount, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return totalCount, err
	}

	var results *sql.Rows
	results, err = db.Query("SELECT count(*) as count_users FROM users")
	if err != nil {
		return totalCount, err
	}

	var count_users int64
	for results.Next() {
		err = results.Scan(&count_users)
		if err != nil {
			return totalCount, err
		}
		totalCount += count_users
	}
	return totalCount, nil
}

func TotalUserCountVerifiedAuthSphere() (int64, error) {
	var totalCount int64

	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return totalCount, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return totalCount, err
	}

	var results *sql.Rows
	results, err = db.Query("SELECT count(*) as count_users FROM users WHERE is_verified = 1")
	if err != nil {
		return totalCount, err
	}

	var count_users int64
	for results.Next() {
		err = results.Scan(&count_users)
		if err != nil {
			return totalCount, err
		}
		totalCount += count_users
	}
	return totalCount, nil
}

//// SECTION FOR BLACKLIST ////

func GetTotalBlackListCountApplication(app Application) (int64, error) {
	var totalCount int64

	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return totalCount, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return totalCount, err
	}

	var results *sql.Rows
	results, err = db.Query("SELECT count(*) as count_blacklists FROM application_blacklist WHERE app_secret = ?", app.Secret)
	if err != nil {
		return totalCount, err
	}

	var count_blacklists int64
	for results.Next() {
		err = results.Scan(&count_blacklists)
		if err != nil {
			return totalCount, err
		}
		totalCount += count_blacklists
	}
	return totalCount, nil
}

func AddBlacklistToApp(secret, data, btype string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// save blacklist
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var insertBlacklist *sql.Stmt
	insertBlacklist, err = tx.Prepare("INSERT INTO application_blacklist (app_secret, id, data, type) VALUES (?, ?, ?, ?)")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer insertBlacklist.Close()

	// generate unique id for blacklist
	id := RandomString(16)

	// check if license was added
	var result sql.Result
	result, err = insertBlacklist.Exec(secret, id, data, btype)
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

func RemoveAllBlacklists(app Application) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// remove all variables
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var removeBlacklist *sql.Stmt
	removeBlacklist, err = tx.Prepare("DELETE FROM application_blacklist WHERE app_secret = ?")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer removeBlacklist.Close()

	// check if variables were deleted
	var result sql.Result
	result, err = removeBlacklist.Exec(app.Secret)
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

func RemoveBlacklist(app Application, id string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// remove blacklist
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var removeBlacklist *sql.Stmt
	removeBlacklist, err = tx.Prepare("DELETE FROM application_blacklist WHERE app_secret = ? AND id = ?")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer removeBlacklist.Close()

	// check if license was deleted
	var result sql.Result
	result, err = removeBlacklist.Exec(app.Secret, id)
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

func GetApplicationBlacklist(secret, id string) (Blacklist, error) {
	var blacklist Blacklist
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return blacklist, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return blacklist, err
	}

	results, err := db.Query("SELECT * FROM application_blacklist WHERE app_secret = ? AND id = ?", secret, id)
	if err != nil {
		return blacklist, err
	}

	for results.Next() {

		err = results.Scan(&blacklist.App_Secret, &blacklist.Blacklist_Data, &blacklist.Blacklist_Type, &blacklist.ID)
		if err != nil {
			return blacklist, err
		}
	}
	return blacklist, err
}

func GetBlacklists(app_secret string) ([]Blacklist, error) {
	var blacklists []Blacklist
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return blacklists, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return blacklists, err
	}

	results, err := db.Query("SELECT * FROM application_blacklist WHERE app_secret = ?", app_secret)
	if err != nil {
		return blacklists, err
	}

	for results.Next() {
		var each = Blacklist{}
		err = results.Scan(&each.App_Secret, &each.ID, &each.Blacklist_Type, &each.Blacklist_Data)
		if err != nil {
			return blacklists, err
		}

		blacklists = append(blacklists, each)
	}

	return blacklists, err
}

//// SECTION FOR VARIABLES ////

func GetTotalVariableCountApplication(app Application) (int64, error) {
	var totalCount int64

	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return totalCount, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return totalCount, err
	}

	var results *sql.Rows
	results, err = db.Query("SELECT count(*) as count_variables FROM application_variables WHERE app_secret = ?", app.Secret)
	if err != nil {
		return totalCount, err
	}

	var count_variables int64
	for results.Next() {
		err = results.Scan(&count_variables)
		if err != nil {
			return totalCount, err
		}
		totalCount += count_variables
	}
	return totalCount, nil
}

func RemoveVariable(app Application, variable_secret string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// remove variable
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var removeVariable *sql.Stmt
	removeVariable, err = tx.Prepare("DELETE FROM application_variables WHERE app_secret = ? AND var_secret = ?")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer removeVariable.Close()

	// check if license was deleted
	var result sql.Result
	result, err = removeVariable.Exec(app.Secret, variable_secret)
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

func RemoveAllVariables(app Application) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// remove all variables
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var removeVariable *sql.Stmt
	removeVariable, err = tx.Prepare("DELETE FROM application_variables WHERE app_secret = ?")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer removeVariable.Close()

	// check if variables were deleted
	var result sql.Result
	result, err = removeVariable.Exec(app.Secret)
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

func UpdateAppVariable(secret, newValue string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	stmt, err := db.Prepare("UPDATE application_variables SET var_value = ? WHERE var_secret = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(newValue, secret)
	if err != nil {
		return err
	}
	return nil
}

func AddVariableToApp(secret, name, value string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// save variable
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var insertApp *sql.Stmt
	insertApp, err = tx.Prepare("INSERT INTO application_variables (app_secret, var_secret, var_name, var_value) VALUES (?, ?, ?, ?)")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer insertApp.Close()

	// generate unique secret for variable
	variable_secret := RandomString(16)

	// check if license was added
	var result sql.Result
	result, err = insertApp.Exec(secret, variable_secret, name, value)
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

func GetApplicationVariable(secret, variable_secret string) (Variable, error) {
	var variable Variable
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return variable, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return variable, err
	}

	results, err := db.Query("SELECT * FROM application_variables WHERE app_secret = ? AND var_secret = ?", secret, variable_secret)
	if err != nil {
		return variable, err
	}

	for results.Next() {

		err = results.Scan(&variable.App_Secret, &variable.Variable_Secret, &variable.Variable_Name, &variable.Variable_Value)
		if err != nil {
			return variable, err
		}
	}
	return variable, err
}

func GetVariables(app_secret string) ([]Variable, error) {
	var variables []Variable
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return variables, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return variables, err
	}

	results, err := db.Query("SELECT * FROM application_variables WHERE app_secret = ?", app_secret)
	if err != nil {
		return variables, err
	}

	for results.Next() {
		var each = Variable{}
		err = results.Scan(&each.App_Secret, &each.Variable_Secret, &each.Variable_Name, &each.Variable_Value)
		if err != nil {
			return variables, err
		}

		variables = append(variables, each)
	}

	return variables, err
}

//// SECTION FOR PAYMENTS ////

func RemovePayment(u User, payment_id string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// remove payment
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var removeLog *sql.Stmt
	removeLog, err = tx.Prepare("DELETE FROM payments WHERE status = ? and userid = ? AND payment_id = ?")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer removeLog.Close()

	// check if payment was deleted
	var result sql.Result
	result, err = removeLog.Exec("VOIDED", u.ID, payment_id)
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

func UpdatePayment(uniqid, status string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	stmt, err := db.Prepare("UPDATE payments SET status = ? WHERE payment_id = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(status, uniqid)
	if err != nil {
		return err
	}
	return nil
}

func GetPayments(userid string) ([]Payment, error) {
	var payment []Payment
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return payment, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return payment, err
	}

	results, err := db.Query("SELECT * FROM payments WHERE userid = ?", userid)
	if err != nil {
		return payment, err
	}

	for results.Next() {
		var each = Payment{}
		err = results.Scan(&each.UserID, &each.PaymentID, &each.Created_At, &each.Gateway, &each.Amount, &each.Status)
		if err != nil {
			return payment, err
		}

		if each.Status == "PENDING" {
			each.Color = settings.YellowColor
		} else if each.Status == "VOIDED" {
			each.Color = "tomato"
		} else {
			each.Color = "#d7fada"
		}

		payment = append(payment, each)
	}

	return payment, err
}

//// SECTION FOR PANEL LOGS ////

func RemoveLog(app Application, logid string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// remove user
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var removeLog *sql.Stmt
	removeLog, err = tx.Prepare("DELETE FROM application_logs WHERE app_secret = ? AND logid = ?")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer removeLog.Close()

	// check if user was deleted
	var result sql.Result
	result, err = removeLog.Exec(app.Secret, logid)
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

//// SECTION FOR PANEL SETTINGS ////

func UpdateApplicationSettings(antiVPN, enableIntegrityCheck, appHash, enableAppUpdates, appVersion, appUpdateLink, status string, u User, app Application) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	stmt, err := db.Prepare("UPDATE applications SET antivpn = ?, int_check = ?, app_hash = ?, app_version = ?, updt_check = ?, update_link = ?, status = ? WHERE secret = ? AND owner = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(antiVPN, enableIntegrityCheck, appHash, appVersion, enableAppUpdates, appUpdateLink, status, app.Secret, u.ID)
	if err != nil {
		return err
	}
	return nil
}

//// SECTION FOR APPLICATION USERS ////

func UpdateAppUser(u Application_User, newEmail, newIP, newPassword, newExpires, newHWID, newLastLogin, newCreatedAt, newBanned, newVariable, newLevel string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	var passToUse string

	if newPassword != "" && newPassword != " " {
		passToUse, err = HashPassword(newPassword)
		if err != nil {
			return err
		}
	} else {
		passToUse = u.Password
	}

	stmt, err := db.Prepare("UPDATE application_users SET email = ?, ip = ?, password = ?, exp_date = ?, hwid = ?, last_login = ?, created_at = ?, banned = ?, var = ?, level = ? WHERE app_secret = ? AND username = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(newEmail, newIP, passToUse, newExpires, newHWID, newLastLogin, newCreatedAt, newBanned, newVariable, newLevel, u.App_Secret, u.Username)
	if err != nil {
		return err
	}
	return nil
}

func GetApplicationUser(secret, username string) (Application_User, error) {
	var user Application_User
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return user, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return user, err
	}

	results, err := db.Query("SELECT * FROM application_users WHERE app_secret = ? AND username = ?", secret, username)
	if err != nil {
		return user, err
	}

	for results.Next() {

		err = results.Scan(&user.App_Secret, &user.Username, &user.Email, &user.IP, &user.Password, &user.Exp_Date, &user.Expired, &user.HWID, &user.Last_Login, &user.Created_At, &user.Banned, &user.Variable, &user.Level)
		if err != nil {
			return user, err
		}
	}

	return user, err
}

func AppUserExists(username string, app Application) (bool, error) {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return true, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return true, err
	}

	row := db.QueryRow("SELECT username FROM application_users WHERE username = ? AND app_secret = ?", username, app.Secret).Scan(&username)
	if row != nil {
		return false, nil
	}

	return true, err
}

func AddAppUser(app Application, username, password string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// add user to db
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var insertApp *sql.Stmt
	insertApp, err = tx.Prepare("INSERT INTO application_users (app_secret, username, email, ip, password, exp_date, expired, hwid, last_login, created_at, banned, var, level) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer insertApp.Close()

	// checks to set expiration

	hashedPassword, err := HashPassword(password)
	if err != nil {
		return err
	}

	expTime := GetLifetimeExpiration()
	currentDate := GetCurrentTime()

	// check if user was added
	var result sql.Result
	result, err = insertApp.Exec(app.Secret, username, "N/A", "N/A", hashedPassword, expTime, "0", "N/A", "N/A", currentDate, "0", "", "0")
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

//// SECTION FOR USERS ////

func GetTotalUserCountApplication(app Application) (int64, error) {
	var totalCount int64

	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return totalCount, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return totalCount, err
	}

	var results *sql.Rows
	results, err = db.Query("SELECT count(*) as count_users FROM application_users WHERE app_secret = ?", app.Secret)
	if err != nil {
		return totalCount, err
	}

	var count_users int64
	for results.Next() {
		err = results.Scan(&count_users)
		if err != nil {
			return totalCount, err
		}
		totalCount += count_users
	}
	return totalCount, nil
}

func RemoveAllUsers(app Application) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// remove all users
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var removeUsers *sql.Stmt
	removeUsers, err = tx.Prepare("DELETE FROM application_users WHERE app_secret = ?")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer removeUsers.Close()

	// check if users were deleted
	var result sql.Result
	result, err = removeUsers.Exec(app.Secret)
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

func ResetAllHWIDs(app Application) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	stmt, err := db.Prepare("UPDATE application_users SET hwid = ? WHERE app_secret = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec("N/A", app.Secret)
	if err != nil {
		return err
	}
	return nil
}

func ResetUserHWID(app Application, username string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	stmt, err := db.Prepare("UPDATE application_users SET hwid = ? WHERE app_secret = ? AND username = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec("N/A", app.Secret, username)
	if err != nil {
		return err
	}
	return nil
}

func RemoveAllExpiredUsers(app Application) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// remove user
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var removeLicense *sql.Stmt
	removeLicense, err = tx.Prepare("DELETE FROM application_users WHERE app_secret = ? AND expired = ?")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer removeLicense.Close()

	// check if user was deleted
	var result sql.Result
	result, err = removeLicense.Exec(app.Secret, "1")
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

func RemoveUser(app Application, username string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// remove user
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var removeLicense *sql.Stmt
	removeLicense, err = tx.Prepare("DELETE FROM application_users WHERE app_secret = ? AND username = ?")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer removeLicense.Close()

	// check if user was deleted
	var result sql.Result
	result, err = removeLicense.Exec(app.Secret, username)
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

func SetUserExpired(user Application_User, expired string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	stmt, err := db.Prepare("UPDATE application_users SET expired = ? WHERE app_secret = ? AND username = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(expired, user.App_Secret, user.Username)
	if err != nil {
		return err
	}
	return nil
}

func BanUser(secret, username string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	stmt, err := db.Prepare("UPDATE application_users SET banned = ? WHERE app_secret = ? AND username = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec("1", secret, username)
	if err != nil {
		return err
	}
	return nil
}

func GetUsers(app_secret string) ([]Application_User, error) {
	var users []Application_User
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return users, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return users, err
	}

	results, err := db.Query("SELECT * FROM application_users WHERE app_secret = ?", app_secret)
	if err != nil {
		return users, err
	}

	for results.Next() {
		var user = Application_User{}
		err = results.Scan(&user.App_Secret, &user.Username, &user.Email, &user.IP, &user.Password, &user.Exp_Date, &user.Expired, &user.HWID, &user.Last_Login, &user.Created_At, &user.Banned, &user.Variable, &user.Level)
		if err != nil {
			return users, err
		}

		// set user expired color depending on date
		if UserExpired(user.Exp_Date, GetCurrentTime()) {
			if user.Expired == "0" {
				err := SetUserExpired(user, "1")
				if err != nil {
					panic(err)
				}
				user.Expired = "1"
			}
			user.Color = "tomato"
			user.Exp_Date = "EXPIRED"
		} else {
			if user.Expired == "1" {
				err := SetUserExpired(user, "0")
				if err != nil {
					panic(err)
				}
				user.Expired = "0"
			}
			user.Color = "#d7fada"
		}

		if user.Banned == "1" {
			user.ColorBanned = "tomato"
			user.Banned = "yes"
		} else {
			user.ColorBanned = "#d7fada"
			user.Banned = "no"
		}

		users = append(users, user)
	}

	return users, err
}

//// SECTION FOR LICENSES ////

func UnuseLicense(app Application, license string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	stmt, err := db.Prepare("UPDATE licenses SET used = ?, used_by = ? WHERE license = ? AND app_secret = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec("no", "N/A", license, app.Secret)
	if err != nil {
		return err
	}
	return nil
}

func GetTotalLicenseCountApplication(app Application, isUsed string) (int64, error) {
	var totalCount int64

	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return totalCount, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return totalCount, err
	}

	var results *sql.Rows
	if isUsed == "all" {
		results, err = db.Query("SELECT count(*) as count_licenses FROM licenses WHERE app_secret = ?", app.Secret)
		if err != nil {
			return totalCount, err
		}
	} else {
		results, err = db.Query("SELECT count(*) as count_licenses FROM licenses WHERE app_secret = ? AND used = ?", app.Secret, isUsed)
		if err != nil {
			return totalCount, err
		}
	}

	var count_licenses int64
	for results.Next() {
		err = results.Scan(&count_licenses)
		if err != nil {
			return totalCount, err
		}
		totalCount += count_licenses
	}
	return totalCount, nil
}

func GetTotalLogApplicationCount(app Application) (int64, error) {

	var totalCount int64

	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return totalCount, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return totalCount, err
	}

	var results *sql.Rows
	results, err = db.Query("SELECT count(*) as count_logs FROM application_logs WHERE app_secret = ?", app.Secret)
	if err != nil {
		return totalCount, err
	}

	var count_logs int64
	for results.Next() {
		err = results.Scan(&count_logs)
		if err != nil {
			return totalCount, err
		}
		totalCount += count_logs
	}
	return totalCount, nil
}

func GetTotalLogCount(u User) (int64, error) {

	var totalCount int64

	apps, err := GetApplications(u.ID)
	if err != nil {
		return totalCount, err
	}

	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return totalCount, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return totalCount, err
	}

	for _, app := range apps {
		results, err := db.Query("SELECT count(*) as count_logs FROM application_logs WHERE app_secret = ?", app.Secret)
		if err != nil {
			return totalCount, err
		}
		var count_logs int64
		for results.Next() {
			err = results.Scan(&count_logs)
			if err != nil {
				return totalCount, err
			}
			totalCount += count_logs
		}
	}
	return totalCount, nil
}

func GetTotalLicenseCount(u User) (int64, error) {

	var totalCount int64

	apps, err := GetApplications(u.ID)
	if err != nil {
		return totalCount, err
	}

	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return totalCount, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return totalCount, err
	}

	for _, app := range apps {
		results, err := db.Query("SELECT count(*) as count_licenses FROM licenses WHERE app_secret = ?", app.Secret)
		if err != nil {
			return totalCount, err
		}
		var count_licenses int64
		for results.Next() {
			err = results.Scan(&count_licenses)
			if err != nil {
				return totalCount, err
			}
			totalCount += count_licenses
		}
	}
	return totalCount, nil

}

func RemoveAllUsedLicenses(app Application) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// remove all licenses
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var removeLicense *sql.Stmt
	removeLicense, err = tx.Prepare("DELETE FROM licenses WHERE app_secret = ? AND used = ?")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer removeLicense.Close()

	// check if licenses were deleted
	var result sql.Result
	result, err = removeLicense.Exec(app.Secret, "yes")
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

func RemoveAllUnusedLicenses(app Application) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// remove all licenses
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var removeLicense *sql.Stmt
	removeLicense, err = tx.Prepare("DELETE FROM licenses WHERE app_secret = ? AND used = ?")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer removeLicense.Close()

	// check if licenses were deleted
	var result sql.Result
	result, err = removeLicense.Exec(app.Secret, "no")
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

func RemoveAllLicenses(app Application) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// remove all licenses
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var removeLicense *sql.Stmt
	removeLicense, err = tx.Prepare("DELETE FROM licenses WHERE app_secret = ?")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer removeLicense.Close()

	// check if licenses were deleted
	var result sql.Result
	result, err = removeLicense.Exec(app.Secret)
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

func RemoveLicense(app Application, license string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// remove application
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var removeLicense *sql.Stmt
	removeLicense, err = tx.Prepare("DELETE FROM licenses WHERE app_secret = ? AND license = ?")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer removeLicense.Close()

	// check if license was deleted
	var result sql.Result
	result, err = removeLicense.Exec(app.Secret, license)
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

func GetLicenses(app_secret string) ([]License, error) {
	var licenses []License
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return licenses, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return licenses, err
	}

	results, err := db.Query("SELECT * FROM licenses WHERE app_secret = ?", app_secret)
	if err != nil {
		return licenses, err
	}

	for results.Next() {
		var each = License{}
		err = results.Scan(&each.App_Secret, &each.License, &each.Exp, &each.Level, &each.Used, &each.Used_By)
		if err != nil {
			return licenses, err
		}

		// set license color depending on if its used or not
		if each.Used == "no" {
			each.Color = "tomato"
		} else {
			each.Color = "#d7fada"
		}

		licenses = append(licenses, each)
	}

	return licenses, err
}

func AddLicensesToApp(u User, amount, length int, secret, prefix, exp, level, format string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// save licenses
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	for i := 0; i < amount; i++ { // create specific amount of licenses
		var insertApp *sql.Stmt
		insertApp, err = tx.Prepare("INSERT INTO licenses (app_secret, license, exp, level, used, used_by) VALUES (?, ?, ?, ?, ?, ?)")
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				return err
			}
		}
		defer insertApp.Close()

		// generate depending on settings
		license := GenerateLicense(prefix, length, format)

		// check if license was added
		var result sql.Result
		result, err = insertApp.Exec(secret, license, exp, level, "no", "N/A")
		aff, _ := result.RowsAffected()
		if aff == 0 {
			return err
		}
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				return err
			}
			return err
		}
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

//// END OF LICENSE SECTION ////

func UpdatePasswordHash(u User_Verification, newHash string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	stmt, err := db.Prepare("UPDATE users SET password = ? WHERE username = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(newHash, u.Username)
	if err != nil {
		return err
	}
	return nil

}

func Remove2FACodeFromUser(u User_Verification) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	stmt, err := db.Prepare("UPDATE user_verification SET enabled2FA = ?, secret2FA = ?, qrcode = ? WHERE email = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec("0", "N/A", "", u.Email)
	if err != nil {
		return err
	}
	return nil
}

func Add2FACodeToUser(u User_Verification, key, qrCode string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	stmt, err := db.Prepare("UPDATE user_verification SET enabled2FA = ?, secret2FA = ?, qrcode = ? WHERE email = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec("1", key, qrCode, u.Email)
	if err != nil {
		return err
	}
	return nil
}

func ActivateUserAccount(u User_Verification) error {

	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	stmt, err := db.Prepare("UPDATE users SET is_verified = true WHERE username = ? AND email = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(u.Username, u.Email)
	if err != nil {
		return err
	}
	return nil

}

func UpdateVerificationHashForEmail(verificationHash, email string) error {

	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	expirationTime := GetPasswordExpirationDate()

	stmt, err := db.Prepare("UPDATE user_verification SET code = ?, timeout_pass = ? WHERE email = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(verificationHash, expirationTime, email)
	if err != nil {
		return err
	}
	return nil
}

func GetApplication(u User, secret string) (Application, error) {
	var app Application
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return app, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return app, err
	}

	row := db.QueryRow("SELECT * FROM applications WHERE secret = ? AND owner = ?", secret, u.ID).Scan(&app.Name, &app.Secret, &app.Pub_Key, &app.Priv_Key, &app.Status, &app.Owner, &app.Integrity_Check, &app.Application_Hash, &app.Application_Version, &app.Update_Check, &app.Update_Link, &app.AntiVPN)
	if row != nil {
		return app, nil
	}

	return app, err
}

func RemoveAllLogs(app Application) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// remove all logs
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var removeLog *sql.Stmt
	removeLog, err = tx.Prepare("DELETE FROM application_logs WHERE app_secret = ?")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer removeLog.Close()

	// check if licenses were deleted
	var result sql.Result
	result, err = removeLog.Exec(app.Secret)
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

func GetApplicationLogs(app Application) ([]Application_Log, error) {
	var logs []Application_Log
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return logs, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return logs, err
	}

	results, err := db.Query("SELECT * FROM application_logs WHERE app_secret = ?", app.Secret)
	if err != nil {
		return logs, err
	}

	for results.Next() {
		var each = Application_Log{}
		err = results.Scan(&each.App_Secret, &each.LogID, &each.Time, &each.Username, &each.Action)
		if err != nil {
			return logs, err
		}

		logs = append(logs, each)
	}

	return logs, err
}

func UpdateApplicationKeyPair(secret string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// generate new keypair
	privateKey, publicKey := GetRSAKeys()

	stmt, err := db.Prepare("UPDATE applications SET pub_key = ?, priv_key = ? WHERE secret = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(publicKey, privateKey, secret)
	if err != nil {
		return err
	}
	return nil
}

func UpdateApplicationSecret(secret string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// generate new app secret
	newSecret := RandomString(32)

	stmt, err := db.Prepare("UPDATE applications SET secret = ? WHERE secret = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(newSecret, secret)
	if err != nil {
		return err
	}
	return nil
}

func UpdateApplicationName(secret, name string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	stmt, err := db.Prepare("UPDATE applications SET name = ? WHERE secret = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(name, secret)
	if err != nil {
		return err
	}
	return nil
}

func GetApplications(userid string) ([]Application, error) {
	var apps []Application
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return apps, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return apps, err
	}

	results, err := db.Query("SELECT * FROM applications WHERE owner = ?", userid)
	if err != nil {
		return apps, err
	}

	for results.Next() {
		var each = Application{}
		err = results.Scan(&each.Name, &each.Secret, &each.Pub_Key, &each.Priv_Key, &each.Status, &each.Owner, &each.Integrity_Check, &each.Application_Hash, &each.Application_Version, &each.Update_Check, &each.Update_Link, &each.AntiVPN)
		if err != nil {
			return apps, err
		}

		// Check app status and set color
		if each.Status == "active" {
			each.Color = "#d7fada"
		} else if each.Status == "paused" {
			each.Color = settings.YellowColor
		} else {
			each.Color = "tomato"
		}

		apps = append(apps, each)
	}

	return apps, err
}

func AppAlreadyExists(name string) (bool, error) {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return true, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return true, err
	}

	row := db.QueryRow("SELECT name FROM applications WHERE name = ?", name).Scan(&name)
	if row != nil {
		return false, nil
	}

	return true, err
}

func RemoveApplication(u User, secret string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// remove application
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var removeApp *sql.Stmt
	removeApp, err = tx.Prepare("DELETE FROM applications WHERE owner = ? AND secret = ?")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer removeApp.Close()

	// check if user was added
	var result sql.Result
	result, err = removeApp.Exec(u.ID, secret)
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	// also remove any existing licenses and users
	tempApp := Application{Secret: secret}

	err = RemoveAllLicenses(tempApp)
	if err != nil {
		return err
	}

	err = RemoveAllUsers(tempApp)
	if err != nil {
		return err
	}

	err = RemoveAllVariables(tempApp)
	if err != nil {
		return err
	}

	err = RemoveAllLogs(tempApp)
	if err != nil {
		return err
	}

	return nil
}

func AddNewApplication(u User, name string) error {

	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// save user
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var insertApp *sql.Stmt
	insertApp, err = tx.Prepare("INSERT INTO applications (name, secret, pub_key, priv_key, status, owner, int_check, app_hash, app_version, updt_check, update_link, antivpn) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer insertApp.Close()

	// generate new app secret
	secret := RandomString(32)

	// generate new public and private rsa key pair
	privKey, pubKey := GetRSAKeys()

	// check if user was added
	var result sql.Result
	result, err = insertApp.Exec(name, secret, pubKey, privKey, "active", u.ID, "0", "", "1.0", "0", "", "0")
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

func GetUserData(username string) (User, error) {
	var user User
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return user, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return user, err
	}

	results, err := db.Query("SELECT * FROM users WHERE username = ?", username)
	if err != nil {
		return user, err
	}

	for results.Next() {

		err = results.Scan(&user.ID, &user.Username, &user.Password, &user.Email, &user.Active_Plan, &user.Group, &user.IsVerified, &user.CreatedAt, &user.RegisteredIP, &user.SubExp)
		if err != nil {
			return user, err
		}
	}

	return user, err
}

func GetUserByEmail(email string) (User, error) {
	var user User
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return user, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return user, err
	}

	results, err := db.Query("SELECT * FROM users WHERE email = ?", email)
	if err != nil {
		return user, err
	}

	for results.Next() {

		err = results.Scan(&user.ID, &user.Username, &user.Password, &user.Email, &user.Active_Plan, &user.Group, &user.IsVerified, &user.CreatedAt, &user.RegisteredIP, &user.SubExp)
		if err != nil {
			return user, err
		}
	}

	return user, err
}

func EmailTaken(email string) (bool, error) {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return true, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return true, err
	}

	row := db.QueryRow("SELECT email FROM users WHERE email = ?", email).Scan(&email)
	if row != nil {
		return false, nil
	}

	return true, err
}

func UserExists(username string) (bool, error) {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return true, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return true, err
	}

	row := db.QueryRow("SELECT username FROM users WHERE username = ?", username).Scan(&username)
	if row != nil {
		return false, nil
	}

	return true, err
}

func GetUserVerificationData(username string) (User_Verification, error) {
	var user User_Verification
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return user, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return user, err
	}

	results, err := db.Query("SELECT * FROM user_verification WHERE username = ?", username)
	if err != nil {
		return user, err
	}

	for results.Next() {

		err = results.Scan(&user.Email, &user.Username, &user.Code, &user.Timeout, &user.Timeout_Pass, &user.Enabled2FA, &user.Secret2FA, &user.QRCode)
		if err != nil {
			return user, err
		}
	}

	return user, err
}

func AddUserVerification(email, username, code, timeout string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// save user
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var insertVerifcationCode *sql.Stmt
	insertVerifcationCode, err = tx.Prepare("INSERT INTO user_verification (email, username, code, timeout, timeout_pass, enabled2FA, secret2FA, qrcode) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer insertVerifcationCode.Close()

	// check if user was added
	var result sql.Result
	result, err = insertVerifcationCode.Exec(email, username, code, timeout, "", "0", "N/A", "")
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

func AddNewUser(email, username, password, ip string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		return err
	}

	hashedPassword, err := HashPassword(password)
	if err != nil {
		return err
	}

	uniqueID := RandomString(8)

	CreatedAt := GetCurrentTime()
	expirationTimeout := GetVerificationExpirationDate()

	// Email verification code
	emailCode := RandomString(64)
	emailCodeHashed, err := HashPassword(emailCode)
	if err != nil {
		return err
	}

	// save user
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var insertUser *sql.Stmt
	insertUser, err = tx.Prepare("INSERT INTO users (id, username, password, email, active_plan, active_group, is_verified, createdAt, ip_registered, sub_exp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer insertUser.Close()

	// check if user was added
	var result sql.Result
	result, err = insertUser.Exec(uniqueID, username, hashedPassword, email, "free", "user", 0, CreatedAt, ip, "N/A")
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	// send email after user was added

	err = AddUserVerification(email, username, emailCodeHashed, expirationTimeout)
	if err != nil {
		return err
	}

	err = SendEmail(username, email, emailCode)
	if err != nil {
		return err
	}

	return nil
}

//// SECTION FOR USER LOGIN HISTORY ////

func RemoveLoginLog(u User, ip, browser string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// remove log
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var removeLog *sql.Stmt
	removeLog, err = tx.Prepare("DELETE FROM user_login_history WHERE userid = ? AND ip = ? AND browser = ?")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer removeLog.Close()

	// check if log was removed
	var result sql.Result
	result, err = removeLog.Exec(u.ID, ip, browser)
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	return nil
}

func AddLoginLog(ip, browser string, u User) error {
	allHistory, err := GetAllLoginHistorys(u)
	if err != nil {
		return err
	}

	// check if ip and browser info already exist
	var alreadyExists bool
	for _, history := range allHistory {
		storedIP := history.IP
		storedBrowser := history.Browser

		if storedIP == ip && storedBrowser == browser {
			// ip and browser didnt match in each case
			alreadyExists = true
		}
	}

	if !alreadyExists {
		// save log

		db, err := sql.Open(DBType, DBConnect)
		if err != nil {
			return err
		}
		defer db.Close()

		err = db.Ping()
		if err != nil {
			return err
		}

		var tx *sql.Tx
		tx, err = db.Begin()
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				return err
			}
		}
		defer tx.Rollback()

		var insertUser *sql.Stmt
		insertUser, err = tx.Prepare("INSERT INTO user_login_history (userid, time, ip, browser) VALUES (?, ?, ?, ?)")
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				return err
			}
		}
		defer insertUser.Close()

		currentTime := GetCurrentTime()

		// check if log was added
		var result sql.Result
		result, err = insertUser.Exec(u.ID, currentTime, ip, browser)
		aff, _ := result.RowsAffected()
		if aff == 0 {
			return err
		}
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				return err
			}
			return err
		}

		err = tx.Commit()
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				return err
			}
			return err
		}
	}

	return nil
}

func GetAllLoginHistorys(u User) ([]UserLoginHistory, error) {
	var userHistorys []UserLoginHistory
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return userHistorys, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return userHistorys, err
	}

	results, err := db.Query("SELECT * FROM user_login_history WHERE userid = ?", u.ID)
	if err != nil {
		return userHistorys, err
	}

	for results.Next() {
		var user = UserLoginHistory{}
		err = results.Scan(&user.UserID, &user.Time, &user.IP, &user.Browser)
		if err != nil {
			return userHistorys, err
		}

		userHistorys = append(userHistorys, user)
	}

	return userHistorys, err
}

func UpdateUserAccountPlan(userid, active_plan, expiration string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	stmt, err := db.Prepare("UPDATE users SET active_plan = ?, sub_exp = ? WHERE id = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(active_plan, expiration, userid)
	if err != nil {
		return err
	}
	return nil
}

func UpdateApplicationStatus(secret, status string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	stmt, err := db.Prepare("UPDATE applications SET status = ? WHERE secret = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(status, secret)
	if err != nil {
		return err
	}
	return nil
}

func CheckDBOnline() bool {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return false
	}

	defer db.Close()

	err = db.Ping()
	return err == nil
}
