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
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    meta = sql.MetaData()
    meta.bind = migrate_engine

    consumer_table = sql.Table(
        'consumer_oauth2',
        meta,
        sql.Column('id', sql.String(64), primary_key=True, nullable=False),
        sql.Column('name', sql.String(64), nullable=False),
        sql.Column('description', sql.String(64), nullable=True),
        sql.Column('secret', sql.String(128), nullable=False),
        sql.Column('client_type', 
            sql.Enum('confidential', name='client_type'), nullable=False),
        sql.Column('redirect_uris', sql.Text(), nullable=False),
        sql.Column('grant_type', 
            sql.Enum('authorization_code', name='grant_type'), nullable=False),
        sql.Column('response_type', 
            sql.Enum('code', name='response_type'), nullable=False),
        sql.Column('scopes', sql.Text(), nullable=True),
        sql.Column('extra', sql.Text(), nullable=True))
    consumer_table.create(migrate_engine, checkfirst=True)

    authorization_code_table = sql.Table(
        'authorization_code_oauth2',
        meta,
        sql.Column('code', sql.String(64), primary_key=True, nullable=False),
        sql.Column('consumer_id', sql.String(64), sql.ForeignKey('consumer_oauth2.id'),
                             nullable=False, index=True),
        sql.Column('authorizing_user_id', sql.String(64), nullable=False),
        sql.Column('expires_at', sql.String(64), nullable=False),
        sql.Column('scopes', sql.Text(), nullable=True),
        sql.Column('redirect_uri', sql.String(64), nullable=False),
        sql.Column('state', sql.String(64), nullable=True),
        sql.Column('valid', sql.Boolean(), default=True, nullable=False),
        sql.Column('extra', sql.Text(), nullable=True))
    authorization_code_table.create(migrate_engine, checkfirst=True)

    consumer_credentials_table = sql.Table(
        'consumer_credentials_oauth2',
        meta,
        sql.Column('id', sql.String(64), primary_key=True, nullable=False),
        sql.Column('user_id', sql.String(64), index=True, nullable=False),
        sql.Column('client_id', sql.String(64), sql.ForeignKey('consumer_oauth2.id'),
                             nullable=False, index=True),
        sql.Column('redirect_uri', sql.String(64), nullable=False),
        sql.Column('response_type', sql.Enum('code', name='response_type'), nullable=False),
        sql.Column('state', sql.String(64), nullable=True),
        sql.Column('created_at', sql.DateTime(), default=None, nullable=False),
        sql.Column('extra', sql.Text(), nullable=True))
    consumer_credentials_table.create(migrate_engine, checkfirst=True)

    access_token_table = sql.Table(
        'access_token_oauth2',
        meta,
        sql.Column('id', sql.String(64), primary_key=True, nullable=False),
        sql.Column('consumer_id', sql.String(64), sql.ForeignKey('consumer_oauth2.id'),
                             nullable=False, index=True),
        sql.Column('authorizing_user_id', sql.String(64), nullable=False),
        sql.Column('expires_at', sql.String(64), nullable=False),
        sql.Column('scopes', sql.Text(), nullable=True),
        sql.Column('refresh_token', sql.String(64), nullable=True),
        sql.Column('valid', sql.Boolean(), default=True, nullable=False),
        sql.Column('extra', sql.Text(), nullable=True))
    access_token_table.create(migrate_engine, checkfirst=True)

def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    meta = sql.MetaData()
    meta.bind = migrate_engine

    tables = ['consumer_oauth2', 'authorization_token_oauth2', 'consumer_credentials_oauth2',
                'access_token_oauth2']
    for t in tables:
        table = sql.Table(t, meta, autoload=True)
        table.drop(migrate_engine, checkfirst=True)
