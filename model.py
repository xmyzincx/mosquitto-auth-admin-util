from sqlalchemy import Column, Index, Integer, SmallInteger, Text, text
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
metadata = Base.metadata


class Account(Base):
    __tablename__ = 'account'

    id = Column(Integer, primary_key=True, server_default=text("nextval('account_id_seq'::regclass)"))
    username = Column(Text, nullable=False, index=True)
    password = Column(Text)
    super = Column(SmallInteger, nullable=False, server_default=text("0"))


class Acl(Base):
    __tablename__ = 'acls'
    __table_args__ = (Index('acls_user_topic', 'username', 'topic', unique=True), )

    id = Column(Integer, primary_key=True, server_default=text("nextval('acls_id_seq'::regclass)"))
    username = Column(Text, nullable=False)
    topic = Column(Text, nullable=False)
    rw = Column(Integer, nullable=False, server_default=text("0"))
