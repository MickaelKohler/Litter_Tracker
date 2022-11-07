CREATE TABLE IF NOT EXISTS lt_user (
	user_id SERIAL NOT NULL,
	user_mail VARCHAR(50) NOT NULL UNIQUE,
	user_pwd VARCHAR(255) NOT NULL,
	user_name VARCHAR(50) NOT NULL,
	user_admin BOOLEAN NOT NULL,
	user_datetime TIMESTAMP,
	PRIMARY KEY(user_id)
);

CREATE TABLE IF NOT EXISTS lt_type (
	type_id SERIAL NOT NULL,
	type_name VARCHAR(10) NOT NULL,
	type_img BYTEA,
	PRIMARY KEY(type_id)
);

CREATE TABLE IF NOT EXISTS lt_classif (
	class_id SERIAL NOT NULL,
	user_id INT,
	type_id INT NOT NULL, 
	class_score NUMERIC(6, 2),
	class_datetime TIMESTAMP,
	class_ok BOOLEAN,
	PRIMARY KEY(class_id),
	CONSTRAINT fk_class
      FOREIGN KEY(type_id) 
	  	REFERENCES lt_type(type_id)
	  	ON DELETE RESTRICT,
      FOREIGN KEY(user_id) 
	  	REFERENCES lt_user(user_id)
	  	ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS lt_report (
	class_id INT NOT NULL UNIQUE,
	report_img BYTEA,
	report_ok BOOLEAN,
	CONSTRAINT fk_report
      FOREIGN KEY(class_id) 
	  	REFERENCES lt_classif(class_id)
	  	ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS lt_message (
	msg_id SERIAL NOT NULL,
	user_id INT,
	msg_name VARCHAR(50),
	msg_mail VARCHAR(50),
	msg_txt VARCHAR(10000),
	msg_datetime TIMESTAMP,
	msg_read BOOLEAN,
	CONSTRAINT fk_message
      FOREIGN KEY(user_id) 
	  	REFERENCES lt_user(user_id)
	  	ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS lt_subscribe (
	sub_mail VARCHAR(50) NOT NULL,
	sub_datetime TIMESTAMP NOT NULL,
	PRIMARY KEY(sub_mail)
);

CREATE TABLE IF NOT EXISTS lt_blocklist (
	block_id SERIAL NOT NULL,
	block_token VARCHAR(50) NOT NULL,
	block_datetime TIMESTAMP NOT NULL,
	PRIMARY KEY(block_id)
);

INSERT INTO lt_type (type_id, type_name, type_img)
VALUES	(0, 'cardboard', pg_read_binary_file('/resources/bin_paper.jpg')),
		(1, 'e-waste', pg_read_binary_file('/resources/bin_ewaste.jpg')),
		(2, 'glass', pg_read_binary_file('/resources/bin_glass.jpg')),
		(3, 'medical', pg_read_binary_file('/resources/bin_mixe.jpg')),
		(4, 'metal', pg_read_binary_file('/resources/bin_metal.jpg')),
		(5, 'paper', pg_read_binary_file('/resources/bin_paper.jpg')),
		(6, 'plastic', pg_read_binary_file('/resources/bin_plastic.jpg'));