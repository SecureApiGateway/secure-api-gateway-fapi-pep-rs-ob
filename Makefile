gcr-repo := sbat-gcr-develop

build-docker: conf
ifndef tag
	$(warning no tag supplied; latest assumed)
	$(eval tag=latest)
endif
	docker build docker/7.0/ig/ -t eu.gcr.io/${gcr-repo}/securebanking/gate/ig:${tag}
	docker push eu.gcr.io/${gcr-repo}/securebanking/gate/ig:${tag}

conf:
	./bin/config.sh init