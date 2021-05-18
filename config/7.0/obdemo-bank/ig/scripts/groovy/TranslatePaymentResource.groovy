
request.uri.path = request.uri.path.replaceFirst("/openbanking/.*?/","/")
next.handle(context, request)
