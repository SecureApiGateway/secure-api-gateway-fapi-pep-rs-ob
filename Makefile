repo := sbat-gcr-develop
service := "gate/ig"

docker: conf
ifndef tag
	$(warning no tag supplied; latest assumed)
	$(eval tag=latest)
endif
	docker build docker/7.1.0/ig/ -t eu.gcr.io/${repo}/securebanking/${service}:${tag}
	docker push eu.gcr.io/${repo}/securebanking/${service}:${tag}

conf:
ifndef env
	$(warning no env supplied; prod assumed)
	$(eval env=prod)
endif
	if [ "${env}" = "prod" ]; then \
  		IG_MODE="production"; \
  	else \
  		IG_MODE="development"; \
  	fi; \
	echo "init config for env: ${env}, igmode: $$IG_MODE\n"; \
	./bin/config.sh init --env ${env} --igmode $${IG_MODE}
