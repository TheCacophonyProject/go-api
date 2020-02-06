# go-api

Client for the [Cacophony API server](https://github.com/TheCacophonyProject/cacophony-api).

## Test Setup
To run the tests you need to setup a cacophony-api instance and add some entries to the SQL DB
- Follow setup the instructions at [Cacophony API server](https://github.com/TheCacophonyProject/cacophony-api)
- Copy SQL file to API docker container `sudo docker cp db-test-seed.sql cacophony-api:/db-seed.sql`
- Run SQL file `sudo docker exec cacophony-api sh -c "sudo -i -u postgres psql cacophonytest -f/db-seed.sql"`
