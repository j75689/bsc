package haber_fix

import _ "embed"

// contract codes for Chapel upgrade
var (
	//go:embed chapel/ValidatorContract
	ChapelValidatorContract string
	//go:embed chapel/SlashContract
	ChapelSlashContract string
)

// contract codes for Rialto upgrade
var (
	//go:embed rialto/ValidatorContract
	RialtoValidatorContract string
	//go:embed rialto/SlashContract
	RialtoSlashContract string
)
