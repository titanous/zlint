zlint
====================

[![Build Status](https://travis-ci.org/zmap/zlint.svg?branch=master)](https://travis-ci.org/zmap/zlint)
[![Go Report Card](https://goreportcard.com/badge/github.com/zmap/zlint)](https://goreportcard.com/report/github.com/zmap/zlint)

Certificate linting, written in Go.

## Building

To install this code:

If you have not already set up a GOPATH, do the following after installing golang to temporarily set one under bash:

`$ mkdir $HOME/godir`

`$ export GOPATH=$HOME/godir`

`$ export PATH=$PATH:$GOPATH/bin`

or for Windows under cmd:

`> mkdir %HOMEPATH%\godir`

`> set GOPATH=%HOMEPATH%\godir`

`> set PATH=%PATH%;%GOPATH%\bin`

Then, simply install certlint:

`$ go get github.com/zmap/zlint`

## Adding a new lint
1. Create the lint 
2. Write tests for the lint
3. Add the lint to the `LintReport` structure in `base.go`
4. MAKE SURE YOU IMPLEMENT THE `UpdateReport` function in the lint
5. Run `gofmt`
