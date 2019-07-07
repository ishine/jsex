#! /bin/bash
# July 7, 2019

if [ -z "$COVERALLS_REPO_TOKEN" ]
then
    echo "Syntax: COVERALLS_REPO_TOKEN=<TOKEN> $0"
    exit 1
fi

which coveralls > /dev/null || pip3 install cpp-coveralls || exit 1

make clean
make COVERAGE=1
./test.sh
gcov src/*.gcno
coveralls -n -e src/cJSON.c
make clean
