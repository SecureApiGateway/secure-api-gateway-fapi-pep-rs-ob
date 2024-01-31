repo := europe-west4-docker.pkg.dev/sbat-gcr-develop/sapig-docker-artifact
service := ig

docker: conf
ifndef tag
	$(warning no tag supplied; latest assumed)
	$(eval tag=latest)
endif
	docker build docker/7.3.0/ig/ -t ${repo}/securebanking/${service}:${tag}
	docker push ${repo}/securebanking/${service}:${tag}

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
