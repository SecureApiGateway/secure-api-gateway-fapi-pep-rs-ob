gcr-repo := sbat-gcr-develop

build-docker: conf
ifndef tag
	$(warning no tag supplied; latest assumed)
	$(eval tag=latest)
endif
	docker build docker/7.1.0/ig/ -t eu.gcr.io/${gcr-repo}/securebanking/gate/ig:${tag}
	docker push eu.gcr.io/${gcr-repo}/securebanking/gate/ig:${tag}

build-docker-ig: conf
ifndef tag
	$(warning no tag supplied; latest assumed)
	$(eval tag=latest)
endif
	docker build docker/7.1.0/ig/ -t eu.gcr.io/${gcr-repo}/securebanking/gate/ig:${tag}
	docker push eu.gcr.io/${gcr-repo}/securebanking/gate/ig:${tag}

conf:
ifndef env
	$(warning no env supplied; dev assumed)
	$(eval env=dev)
endif
	if [ "${env}" = "prod" ]; then \
  		IG_MODE="production"; \
  	else \
  		IG_MODE="development"; \
  	fi; \
	echo "init config for env: ${env}, igmode: $$IG_MODE\n"; \
	./bin/config.sh init --env ${env} --igmode $${IG_MODE}
