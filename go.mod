module github.com/cristalhq/jwt/v5

go 1.19

retract [v5.2.0, v5.3.0] // check 'typ' is too strict (see https://github.com/cristalhq/jwt/pull/150)
