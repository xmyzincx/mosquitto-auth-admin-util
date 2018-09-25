import readline
import sys
from sqlalchemy import create_engine  
from sqlalchemy import Column, String  
from sqlalchemy.ext.declarative import declarative_base  
from sqlalchemy.orm import sessionmaker
from sqlalchemy import exc as exception
import model
from getpass import getpass
import hashing_passwords as hash_util

db_string = "<database>://<db_username>:<db_password>@<db_server_ip>:<db_server_port>/<db_name>"

# For example
# db_string = "postgresql://admin:12345@localhost:5432/mqtt"

db = create_engine(db_string)  
base = declarative_base()

Session = sessionmaker(db)  
session = Session()


# Create User
def create_user(user_name, passwrd):
    hash_passwrd = hash_util.make_hash(passwrd)
    new_user = model.Account(
            username = user_name,
            password = hash_passwrd)
    session.add(new_user)
    try:
        session.commit()
        return True
    except exception.SQLAlchemyError as e:
        session.rollback()
        print("Error: " + e.message)
        return False


# Read all users
def get_all_user():
    try:
        users = session.query(model.Account)  
        for user in users:  
            print(user.username)
    except exception.SQLAlchemyError as e:
        print("Error: " + e.message)


# Update User
def update_password(user_name, new_password):
    user = session.query(model.Account).filter_by(username = user_name).first()
    if user:
        hash_password = hash_util.make_hash(new_password)
        user.password = hash_password
        try:
            session.commit()
            return True
        except exception.SQLAlchemyError as e:
            session.rollback()
            print("Something went wrong while updating the user.")
            print("Error: " + e.message)
            return False
    print("No such user found!")
    return False


# Delete user and its associated rules
def delete_user(user_name):
    user = session.query(model.Account).filter_by(username = user_name)
    if user.first():
        acl_rules_for_user = session.query(model.Acl).filter_by(username = user_name)
        if acl_rules_for_user.first():
            acl_rules_for_user.delete()
        else:
            print("No ACL rules was associated with this user.")
        user.delete()
        try:
            session.commit()
            return True
        except exception.SQLAlchemyError as e:
            session.rollback()
            print("Error: " + e.message)
            return False
    else:
        print("No such user found!")
        return False


def validate_user_pass(user_name, passwrd):
    try:
        user = session.query(model.Account).filter_by(username = user_name).first()
        return  hash_util.check_hash(passwrd, user.password)
    except exception.SQLAlchemyError as e:
        print("Error:" + e.message)
    return False


def is_user(user_name):
    try:
        user = session.query(model.Account).filter_by(username = user_name).first()
        if user is not None:
            return True
        return False
    except exception.SQLAlchemyError as e:
        print("Error: " + e.message)
        return False


# Create ACL rule
def create_acl_rule(user_name, _topic):
    if is_user(user_name):
        try:
            new_acl_rule = model.Acl(username = user_name, topic = _topic, rw = 4)
            session.add(new_acl_rule)
            session.commit()
            return True
        except exception.SQLAlchemyError as e:
            session.rollback()
            print("Error: " + e.message)
    else:
        print("No user found.")
    return False


# Read ACL
def get_all_acl():
    try:
        acl = session.query(model.Acl)
        for item in acl:
            print(item.username, item.topic)
    except exception.SQLAlchemyError as e:
        print("Error: " + e.message)


# Update ACL rule 
def update_acl_rule(user_name, old_topic, new_topic):
    if is_user(user_name):
        acl_rule = session.query(model.Acl).filter_by(username = user_name, topic = old_topic).first()
        if acl_rule:
            acl_rule.topic = new_topic
            try:
                session.commit()
                return True
            except exception.SQLAlchemyError as e:
                session.rollback()
                print("Error: " + e.message)
                return False
        else:
            print("No such ACL rule found!")
            return False
    else:
        print("No such user found.")
        return False


# Delete ACL rule
def delete_acl_rule(user_name, _topic):
    if is_user(user_name):
        acl_rule = session.query(model.Acl).filter_by(username = user_name, topic = _topic)
        if acl_rule.first():
            acl_rule.delete()
            try:
                session.commit()
                return True
            except exception.SQLAlchemyError as e:
                session.rollback()
                print("Error: " + e.message)
                return False
        else:
            print("No such ACL rule found!")
            return False
    else:
        print("No user associated with this rule.")
    return False


def switch_create_user():
    username = raw_input("Please enter valid username: ")
    pw = getpass("Please enter password: ")
    pw2 = getpass("Please re-enter the password: ")

    if pw != pw2:
        print("Passwords don't match!")
        return False
    if create_user(username, pw):
        print("User created!")
        return True
    else:
        print("Apparently it seems like username already exists!!")
        print("No user is created!")
        return False


def switch_get_all_users():
    return get_all_user()


def switch_update_user_password():
    username = raw_input("Please enter valid username: ")
    if is_user(username):
        pw = getpass("Please enter password: ")
        if validate_user_pass(username, pw):
            new_pw = getpass("Please enter new password: ")
            update_password(username, new_pw)
            print("Password has been changed!")
            return True
        else:
            print("Wrong password.")
            return False
    else:
        print("Invalid username")
        return False


def switch_delete_user():
    print("WARNING: User and all its associated ACL rules will be deleted.")
    username = raw_input("Please enter valid username: ")
    if is_user(username):
        pw = getpass("Please enter password: ")
        if validate_user_pass(username, pw):
            if delete_user(username):
                print("User data been deleted")
                return True
        else:
            print("Wrong password")
            return False
    else:
        print("Invalid username")
 
 
def switch_create_acl_rule():
    username = raw_input("Please enter valid username: ")
    topic = raw_input("Please enter a topic: ")
    if create_acl_rule(username, topic):
        print("New rule has been added to the ACL")
    

def switch_get_all_acl():
    return get_all_acl()


def switch_update_acl_rule():
    username = raw_input("Please enter valid username: ")
    if is_user(username):
        old_topic = raw_input("Please enter topic you want to change: ")
        new_topic = raw_input("Please enter new topic: ")
        if update_acl_rule(username, old_topic, new_topic):
            print("ACL rule has been updated")
    else:
        print("No such user found.")


def switch_delete_acl_rule():
    username = raw_input("Please enter valid username: ")
    topic = raw_input("Please enter topic you want to delete: ")
    if delete_acl_rule(username, topic):
        print("ACL rule has been deleted")


switcher = {
        1: switch_create_user,
        2: switch_get_all_users,
        3: switch_update_user_password,
        4: switch_delete_user,
        5: switch_create_acl_rule,
        6: switch_get_all_acl,
        7: switch_update_acl_rule,
        8: switch_delete_acl_rule
        }

if __name__ == '__main__':

   
    opt = 0
    while True:
        print('                                               ')
        print('-----------------------------------------------')
        print('-----------------------------------------------')
        print('CWC MQTT Broker User and ACL Management Utility')
        print('-----------------------------------------------')
        print('-----------------------------------------------')
        print('                                               ')
        print('Please select one of the following option.')
        print('1- Create new user')
        print('2- Get all users')
        print('3- Update user\'s password')
        print('4- Delete user')
        print('5- Create new ACL topic for a user')
        print('6- Get all ACL topics')
        print('7- Update ACL topic for a user')
        print('8- Delete ACL topic for a user')
        print('-----------------------------------------------')
        print('-----------------------------------------------')
        try:
            opt = int(raw_input("Please enter one of the above option (1 - 8): "))
            if opt >= 1 and opt <= 8 and opt != '' and opt != "":
                try:
                    print("Option select: " + str(opt))
                    print('-----------------------------------------------')
                    func = switcher.get(opt)
                    func()
                except KeyboardInterrupt:
                    print("Process interupted")
                    sys.exit(0)
            else:
                print("Invalid option")
        except ValueError:
            print("Invalid option")


