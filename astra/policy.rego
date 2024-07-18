package astra

default allow = false

# SRS
allow {
    valid_token
    service_is("/srs")
    has_role("SFU")
}

# PFQ
allow {
    valid_token
    service_is("/pfq")
    has_role("OU")
}

# CAM
allow {
    valid_token
    service_is("/cam")
    has_role("LAA")
}


service_is(service_name) {
	# http path starts with /<service_name>
	startswith(input.request.Path, service_name)
}

valid_token {
	[_, payload, _] := io.jwt.decode(bearer_token)
	jwks := json.marshal(data.jwks)
	io.jwt.verify_rs256(bearer_token, jwks)
	claims := payload
	claims.exp > time.now_ns() / 1000000000 # Check if token is expired
}

has_role(role) {
	claims := io.jwt.decode(bearer_token)[1]
	roles := claims.roles
	roles[_] == role
}

bearer_token := t {
	v := input.request.headers.Authorization
	startswith(v, "Bearer ")
	t := substring(v, count("Bearer "), -1)
}
