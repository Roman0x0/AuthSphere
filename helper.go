package main

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"math/rand"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/gin-contrib/sessions"
)

const (
	otherSpecialChars = `"#%'()+/:;<=>?[\]^{|}~!@$&*_-.,`
	forbiddenChars    = `"#%'()+/:;<=>?[\]^{|}~!$&*,`
	lowerChars        = `abcdefghijklmnopqrstuvwxyz`
	upperChars        = `ABCDEFGHIJKLMNOPQRSTUVWXYZ`
	digitsChars       = `0123456789`

	DefaultAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	UpperAlphabet   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

func RegisterPassSame(pass1, pass2 string) bool {
	if pass1 == pass2 {
		return true
	} else {
		return false
	}
}

func GenerateLicense(prefix string, length int, format string) string {
	switch format {
	case "XXXX-XXXX-XXXX-XXXX":
		return fmt.Sprintf("%s-%s-%s-%s", RandomStringUpper(4), RandomStringUpper(4), RandomStringUpper(4), RandomStringUpper(4))
	case "[PREFIX]-XXXX-XXXX-XXXX":
		return fmt.Sprintf("%s-%s-%s-%s", prefix, RandomStringUpper(4), RandomStringUpper(4), RandomStringUpper(4))
	case "[PREFIX]-[LENGTH]":
		return fmt.Sprintf("%s-%s", prefix, RandomStringUpper(length))
	default: // XXXX-XXXX-XXXX-XXXX
		return fmt.Sprintf("%s-%s-%s-%s", RandomStringUpper(4), RandomStringUpper(4), RandomStringUpper(4), RandomStringUpper(4))
	}
}

func RandomStringUpper(length int) string {
	id, err := FormatString(generateRandomBuffer, UpperAlphabet, length)
	if err != nil {
		return ""
	}
	return id
}

// BytesGenerator represents random bytes buffer.
type BytesGenerator func(step int) ([]byte, error)

func generateRandomBuffer(step int) ([]byte, error) {
	buffer := make([]byte, step)
	if _, err := rand.Read(buffer); err != nil {
		return nil, err
	}
	return buffer, nil
}

// FormatString generates a random string based on BytesGenerator, alphabet and size.
func FormatString(generateRandomBuffer BytesGenerator, alphabet string, size int) (string, error) {
	mask := 2<<uint32(31-bits.LeadingZeros32(uint32(len(alphabet)-1|1))) - 1
	step := int(math.Ceil(1.6 * float64(mask*size) / float64(len(alphabet))))

	id := new(strings.Builder)
	id.Grow(size)

	for {
		randomBuffer, err := generateRandomBuffer(step)
		if err != nil {
			return "", err
		}

		for i := 0; i < step; i++ {
			currentIndex := int(randomBuffer[i]) & mask

			if currentIndex < len(alphabet) {
				if err := id.WriteByte(alphabet[currentIndex]); err != nil {
					return "", err
				} else if id.Len() == size {
					return id.String(), nil
				}
			}
		}
	}
}

func RandomString(length int) string {
	id, err := FormatString(generateRandomBuffer, DefaultAlphabet, length)
	if err != nil {
		return ""
	}
	return id
}

func GetExpirationDate(licenseExp int) string {
	dt := time.Now()
	return dt.AddDate(0, 0, licenseExp).Format("01-02-2006 15:04:05")
}

func FormatVariables(variables []Variable) string {
	var final string
	for _, variable := range variables {
		final += fmt.Sprintf("%s:%s;", variable.Variable_Secret, variable.Variable_Value)
	}
	return final
}

func RandomInt(n int) string {
	var letters = []rune("0123456789")

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

func GetTotalUsers(apps []Application) (int, error) {
	total := 0

	for _, app := range apps {

		totalLicenses, err := GetTotalUserCountApplication(app)
		if err != nil {
			return total, err
		}

		total += int(totalLicenses)
	}
	return total, nil
}

func GetTotalLicenses(apps []Application) (int, error) {
	total := 0

	for _, app := range apps {

		totalLicenses, err := GetTotalLicenseCountApplication(app, "all")
		if err != nil {
			return total, err
		}

		total += int(totalLicenses)
	}
	return total, nil
}

func GetCurrentTime() string {
	dt := time.Now()
	return dt.Format("01-02-2006 15:04:05")
}

func GetLifetimeExpiration() string {
	dt := time.Now()
	return dt.AddDate(100, 0, 0).Format("01-02-2006 15:04:05")
}

func GetVerificationExpirationDate() string {
	dt := time.Now()
	return dt.Add(time.Minute * 30).Format("01-02-2006 15:04:05")
}

func GetPasswordExpirationDate() string {
	dt := time.Now()
	return dt.Add(time.Minute * 5).Format("01-02-2006 15:04:05")
}

func UserExpired(exp_date, currentTime string) bool {
	convertedExp, err := time.Parse("01-02-2006 15:04:05", exp_date)
	if err != nil {
		return true
	}

	convertedNow, err := time.Parse("01-02-2006 15:04:05", currentTime)
	if err != nil {
		return true
	}

	diff := convertedExp.Sub(convertedNow)
	return diff <= 0
}

func GetAppStatus(value string) string {
	if value == "paused" {
		return "checked"
	}

	return ""
}

func GetCheckValue(value string) string {
	valueConverted, err := strconv.Atoi(value)
	if err != nil {
		return ""
	}

	if valueConverted == 1 {
		return "checked"
	}

	return ""
}

func containsForbiddenCharacters(content string) bool {

	if strings.TrimSpace(content) == "" {
		return true
	}

	for _, c := range strings.Split(content, "") {
		if strings.Contains(forbiddenChars, c) {
			return true
		}
	}
	return false
}

func checkPasswordCriteria(password string) error {

	hasSpecialChars := false
	hasLowerCase := false
	hasUpperCase := false
	hasNumber := false
	hasLength := false

	for _, c := range strings.Split(password, "") {
		switch {
		case strings.Contains(otherSpecialChars, c):
			hasSpecialChars = true
		case strings.Contains(lowerChars, c):
			hasLowerCase = true
		case strings.Contains(upperChars, c):
			hasUpperCase = true
		case strings.Contains(digitsChars, c):
			hasNumber = true
		}
	}

	if len(password) >= 8 {
		hasLength = true
	}

	if !hasSpecialChars || !hasLowerCase || !hasUpperCase || !hasNumber || !hasLength {
		return errors.New("password invalid")
	}
	return nil
}

func checkEmailCriteria(email string) error {
	// check if email is disposable
	for _, emailInList := range emailsToBlock {
		if strings.Contains(email, emailInList) {
			return errors.New("email is not allowed")
		}
	}
	return nil
}

func checkUsernameCriteria(username string) error {
	// Check if username contains only letters and numbers
	var nameAlphaNumeric = true
	for _, char := range username {
		if !unicode.IsLetter(char) && !unicode.IsNumber(char) {
			nameAlphaNumeric = false
		}
	}

	// if the name contains any special unallowed characters then throw an error
	if !nameAlphaNumeric {
		return errors.New("username can only contain letters and numbers")
	}

	// next check if username has a valid length
	var nameLength bool
	if 5 <= len(username) && len(username) <= 50 {
		nameLength = true
	}

	// throws an error because name is either to short or to long
	if !nameLength {
		return errors.New("username must be longer than 4 characters and less than 51")
	}

	return nil
}

func IsAuthenticated(session sessions.Session) bool {
	sessionName := session.Get(settings.SessionName)
	if sessionName == nil {
		return false
	}

	exists, err := UserExists(sessionName.(string))
	if err != nil {
		panic(err)
	}

	if !exists {
		return false
	}

	return true
}

func IsEmailVerified(u User) bool {
	if u.IsVerified == 1 {
		return true
	} else {
		return false
	}
}

func IsAppLocked(app Application) bool {
	if app.Status == "locked" {
		return true
	} else {
		return false
	}
}

func UpdateSubscriptionStatus(u User) {
	currentTime := GetCurrentTime()
	subExpired := UserExpired(u.SubExp, currentTime)
	if subExpired { // subscription expired
		if u.Active_Plan != "free" {
			// Set users plan to free
			UpdateUserAccountPlan(u.ID, "free", "N/A")

			// Lock all current applications except 1 for the user
			apps, err := GetApplications(u.ID)
			if err != nil {
				panic(err)
			}

			// User has more than 1 app
			if len(apps) > 1 {
				// set all other apps on locked
				for i := 1; i < len(apps); i++ {
					err := UpdateApplicationStatus(apps[i].Secret, "locked")
					if err != nil {
						panic(err)
					}
				}
			}
		}
	}
}
