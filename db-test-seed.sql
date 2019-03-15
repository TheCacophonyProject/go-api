-- sudo -i -u postgres psql cacophonytest -f/home/zaza/go/src/github.com/TheCacophonyProject/go-api/db-seed.sql
--docker cp db-seed.sql cacophony-api:/db-seed.sql
-- sudo -i -u postgres psql cacophonytest -f/db-seed.sql

--admin user  admin//password
INSERT INTO "Users" (username, email, password, "globalPermission", "createdAt", "updatedAt") VALUES ('admin_test', 'admin@email.com', '$2a$10$S..GUBx1zVb6r1QklWu5kOgx5czlAPJM1JxeJ0uHAO3nRRhDtNazm', 'write', now(), now());
 
 --test-group
INSERT INTO "Groups" ("id","groupname","createdAt","updatedAt") VALUES (DEFAULT,'test-group','2019-03-14 20:15:23.423 +00:00','2019-03-14 20:15:23.423 +00:00');

--test-password
INSERT INTO "Devices" ("id","devicename","password","public","createdAt","updatedAt","GroupId") VALUES (DEFAULT,'test-device','$2a$10$LWL.Sr0767v0RmWqcgAKduBXSE2G9T2oIn.W5V1ohtgZQA4kKgR06',false,'2019-03-14 20:17:45.636 +00:00','2019-03-14 20:17:45.636 +00:00',1);

