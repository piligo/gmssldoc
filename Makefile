all:	Certificates   ClientFinished   ClientKeyExchange   MasterSecret   ServerFinished ServerKeyExchange 
.PHONY :	all
Certificates:
	go build -mod=vendor cmd/Certificates.go
ClientFinished:
	go build -mod=vendor cmd/$@.go
ClientKeyExchange:
	go build -mod=vendor cmd/$@.go
MasterSecret:
	go build -mod=vendor cmd/$@.go
ServerFinished:
	go build -mod=vendor cmd/$@.go
ServerKeyExchange:
	go build -mod=vendor cmd/$@.go

.PHONY :	clean
clean:
	@rm -fr Certificates   ClientFinished   ClientKeyExchange   MasterSecret   ServerFinished ServerKeyExchange 
