module github.com/Bandeira27/psychoscope-core

go 1.26.0

require (
	github.com/Bandeira27/psychoscope-proto v0.1.0
	google.golang.org/protobuf v1.36.12
)

require golang.org/x/sys v0.49.0 // indirect

replace github.com/Bandeira27/psychoscope-proto => ../psychoscope-proto
