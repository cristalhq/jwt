module github.com/cristalhq/jwt/v5

go 1.19

retract (
	v5.3.0 // check 'typ' is too strict.
	v5.2.0 // check 'typ' is too strict.
)
