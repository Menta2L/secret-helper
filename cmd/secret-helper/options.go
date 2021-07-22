package main

type Options struct {
	Insecure     bool `cli:"-k, --insecure"`
	Version      bool `cli:"-v, --version"`
	Help         bool `cli:"-h, --help"`
	Clobber      bool `cli:"--clobber, --no-clobber"`
	SkipIfExists bool
	Quiet        bool `cli:"--quiet"`

	UseTarget string `cli:"-T, --target" env:"SAFE_TARGET"`

	HelpCommand    struct{} `cli:"help"`
	VersionCommand struct{} `cli:"version"`

	Envvars struct{} `cli:"envvars"`
	Set     struct {
		Provider string `cli:"-p, --provider"`
		Prefix   string `cli:"--prefix"`
	} `cli:"set"`
	List struct {
		Provider string `cli:"-p, --provider"`
		Prefix   string `cli:"--prefix"`
	} `cli:"list"`
	Get struct {
		Provider string `cli:"-p, --provider"`
		Prefix   string `cli:"--prefix"`
	} `cli:"get"`
	Export struct {
		Provider string `cli:"-p, --provider"`
		Prefix   string `cli:"--prefix"`
		Output   string `cli:"-o, --output"`
	} `cli:"export"`
}
