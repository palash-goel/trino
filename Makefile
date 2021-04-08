build:
	./mvnw -pl '!presto-docs,!presto-proxy,!presto-verifier,!presto-benchmark-driver' clean install -nsu -DskipTests
build-main: 
	./mvnw -pl 'presto-spi,presto-main' clean install -nsu -DskipTests
