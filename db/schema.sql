create table users(
  id int primary key auto_increment,
  email varchar(255) unique not null,
  password_hash varchar(255) not null,
  created_at timestamp default current_timestamp
)engine = InnoDB; 

create table refresh_tokens(
    id int primary key auto_increment,
    user_id int not null,
    token_hash varchar(255) not null,
    family_id varchar(255) not null,
    revoked boolean default false,
    expires_at timestamp not null,
    created_at timestamp default current_timestamp,
    foreign key (user_id) references users(id) on delete cascade
) engine = InnoDB;