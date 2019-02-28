path "auth/okta/users/*" {
    capabilities = ["read", "create", "update"]
}

path "auth/token/lookup" {
    capabilities = ["read", "create", "update"]
}

path "identity/lookup/entity" {
    capabilities = ["create","update"]
}

path "keys/*" {
    capabilities = ["read", "create"]
}