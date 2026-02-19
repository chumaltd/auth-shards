#!/bin/bash
# NOTE This script setups the same tables in public + 4 schemas.
# DB password should be supplied from $PGPASSWORD, referred by psqldef.
#   https://github.com/sqldef/sqldef/blob/master/cmd-psqldef.md

create_schema () {
  {
  for i in {1..4}; do
	test_schema="test_$i"
	echo "CREATE SCHEMA $test_schema;"
  done
  } | psqldef --apply \
		-h ${HOSTNAME:-localhost} -p ${PORT:-5432} \
		-U ${USERNAME:-postgres} \
		${DB:-auth_shards}
}

apply_test_ddl () {
  cd $(dirname "${BASH_SOURCE[0]}")/../sql/schema/

  {
	cat *.sqldef.sql

  for i in {1..4}; do
	test_schema="test_$i"
	cat *.sqldef.sql | \
	sed -E 's/"?public"?\./"'"$test_schema"'"./g'
  done
  } | psqldef --apply \
		-h ${HOSTNAME:-localhost} -p ${PORT:-5432} \
		-U ${USERNAME:-postgres} \
		${DB:-auth_shards}
}


echo "CREATE SCHEMA..."
create_schema

echo
echo "CREATE TABLE..."
apply_test_ddl
