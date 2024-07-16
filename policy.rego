package example

default allow = false

allow {
  input.method == "GET"
  input.path == "/public"
}

allow {
  input.method == "POST"
  input.path == "/data"
  input.user == "admin"
}
