DELETE FROM userprofile;
ALTER TABLE userprofile auto_increment = 1;

INSERT INTO userprofile (firstname, lastname, email, password) VALUES ('John', 'Smith', 'johnesmith@example.com', SHA2('testpassword', 256));
INSERT INTO userprofile (firstname, lastname, email, password) VALUES ('Jane', 'Smith', 'janesmith@example.com', SHA2('testpassword', 256));
INSERT INTO userprofile (firstname, lastname, email, password) VALUES ('Foo', 'Bar', 'foobar@example.com', SHA2('testpassword', 256));
INSERT INTO userprofile (firstname, lastname, email, password) VALUES ('Jim', 'Smith', 'jimsmith@example.com', SHA2('testpassword', 256));
INSERT INTO userprofile (firstname, lastname, email, password) VALUES ('Josh', 'Smith', 'joshsmith@example.com', SHA2('testpassword', 256));
INSERT INTO userprofile (firstname, lastname, email, password, userlevel, verified, approved) VALUES ('Admin', '', 'hudsonmichaele@outlook.com', SHA2('password', 256), 'admin', 1, 1);