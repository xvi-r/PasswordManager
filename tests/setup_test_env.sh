#!/bin/bash

export JWT_SECRET="supersecretjwtkey"
export REFRESH_TOKEN_SECRET="supersecretrefreshkey"
export DATABASE="test_users.db"


pytest "$@"
