# Copyright (C) 2014 Universidad Politecnica de Madrid
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import sqlalchemy as sql


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    consumer_table = sql.Table('consumer_oauth2', meta, autoload=True)
    consumer_table.c.response_type.alter(
        sql.Column('response_type',
                   sql.Enum('code', 'token', name='response_type'),
                   nullable=False))

    consumer_credentials_table = sql.Table('consumer_credentials_oauth2', meta, autoload=True)
    consumer_credentials_table.c.response_type.alter(
        sql.Column('response_type',
                   sql.Enum('code', 'token', name='response_type'),
                   nullable=False))

def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    consumer_table = sql.Table('consumer_oauth2', meta, autoload=True)
    consumer_table.c.response_type.alter(
        sql.Column('response_type',
                   sql.Enum('code', name='response_type'),
                   nullable=False))

    consumer_credentials_table = sql.Table('consumer_credentials_oauth2', meta, autoload=True)
    consumer_credentials_table.c.response_type.alter(
        sql.Column('response_type',
                   sql.Enum('code', name='response_type'),
                   nullable=False))
