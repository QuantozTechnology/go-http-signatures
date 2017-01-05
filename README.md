httpsignatures-go
=================
[![GoDoc](https://godoc.org/github.com/QuantozTechnology/go-http-signatures?status.svg)](https://godoc.org/github.com/99designs/httpsignatures-go)
[![Build Status](https://travis-ci.org/QuantozTechnology/go-http-signatures.svg?branch=master)](https://travis-ci.org/QuantozTechnology/go-http-signatures)


Golang middleware library for the [http-signatures spec](https://tools.ietf.org/html/draft-cavage-http-signatures).

## Application
This is server side software, and can be used as middleware in for example the "goji" framework.

## Remarks
When the clockskew check is used, the X-Data header prevails over the Data header.


