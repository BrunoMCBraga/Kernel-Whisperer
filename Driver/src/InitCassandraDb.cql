DROP KEYSPACE Events;
CREATE KEYSPACE Events WITH replication = {'class':'SimpleStrategy', 'replication_factor' : 1};
USE Events;
CREATE TABLE Registry(Timestamp bigint primary key, Pid int, Type ascii, Key varchar, Value varchar);
CREATE TABLE File(Timestamp bigint primary key, Pid int, Type ascii, File varchar);