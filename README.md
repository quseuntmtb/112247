## Llyod's Go Software Engineer Coding Excercise
My code submission the coding excercise, attempting to be as clean as possible but not as verbose as production code.

#### External Dependencies
I tried to avoid using external dependencies / 3rd party pacakges as I felt it was not in the sprit of th exercise.

Two exceptions:
* **`github.com/golang-jwt/jwt/v5`**: Required for the creation and signing of the **HMAC-JWT** (Step 3a).
* **`golang.org/x/crypto/pbkdf2`**: Required for the specific key derivation function **PBKDF2** (Step 1).

**Testing:** 
All unit tests and assertions rely solely on the built-in Go `testing` package, avoiding external test frameworks. Normally you could/would use things like `testify/assert` package to cleanup the code & ensure a level of standard.

#### Step 5: AI Usage Declaration
1. Copilot auto-complete, but _no_ code generation via chat. 
2. Was unaware that of the lack of automatic (PKCS#7) unpadding in the standard Go `cipher` package. When printing output of Step 1, saw it had a lot of empty text around the msg. Spent some time reading go `cipher` docs, could not see anything obvious, so asked Claude (4.5) why I was seeing that output when using golang's `cipher.NewCBCEncrypter()`
3. Boilerplate test generation. I find Copilot decent at generating the 'basic' tests, which I double check like a MR/PR code review, and then add the edgecases myself.