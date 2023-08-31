GIT_COMMIT=$(shell git rev-parse --verify HEAD)

## Prepare the redis database
redis:
	./scripts/initialize-redis.sh

## Prepare mysql database
db: redis
	./scripts/initialize-database.sh


## Prepare basic administrator and keys
init:
	./scripts/initialize-user-and-keys.sh

builder-image:
	docker build -t tommylike/signatrust-builder:$(GIT_COMMIT) -f docker/Dockerfile.openeuler .
client-image:
	docker build -t tommylike/signatrust-client:$(GIT_COMMIT) --build-arg BINARY=client -f docker/Dockerfile .

data-server-image:
	docker build -t tommylike/signatrust-data-server:$(GIT_COMMIT) --build-arg BINARY=data-server -f docker/Dockerfile.data-server .

control-server-image:
	docker build -t tommylike/signatrust-control-server:$(GIT_COMMIT) --build-arg BINARY=control-server -f docker/Dockerfile.control-server .

control-admin-image:
	docker build -t tommylike/signatrust-control-admin:$(GIT_COMMIT) --build-arg BINARY=control-admin -f docker/Dockerfile .

app-image:
	docker build -t tommylike/signatrust-app:$(GIT_COMMIT) -f app/Dockerfile ./app

deploy-local:
	kustomize build ./deploy | kubectl apply -f -