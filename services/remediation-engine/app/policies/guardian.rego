package guardian

default allow = false

# Score thresholds:
# 80-100: ALWAYS BLOCK
# 60-79: BLOCK in prod, PASS in dev/staging
# 0-59: PASS

allow {
    input.score < 60
}

allow {
    input.score >= 60
    input.score < 80
    input.environment != "prod"
}

block {
    not allow
}

reason["Score 80-100 Critical Risk - Hard Block"] {
    input.score >= 80
}

reason["Score 60-79 High Risk - Blocked in Production"] {
    input.score >= 60
    input.score < 80
    input.environment == "prod"
}
