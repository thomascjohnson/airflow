# Copyright 2015 Matthew Pelland (matt@pelland.io)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import flask_login

# Need to expose these downstream
# flake8: noqa: F401
from flask_login import current_user, logout_user, login_required, login_user
# pylint: enable=unused-import

from flask import url_for, redirect, request

from flask_oauthlib.client import OAuth

from airflow import models, configuration, settings
from airflow.configuration import AirflowConfigException
from airflow.utils.db import provide_session
from airflow.utils.log.logging_mixin import LoggingMixin

log = LoggingMixin().log


def get_config_param(param):
    return str(configuration.get('oidc', param))


class OIDCUser(models.User):

    def __init__(self, user):
        self.user = user

    @property
    def is_active(self):
        '''Required by flask_login'''
        return True

    @property
    def is_authenticated(self):
        '''Required by flask_login'''
        return True

    @property
    def is_anonymous(self):
        '''Required by flask_login'''
        return False

    def get_id(self):
        '''Returns the current user id as required by flask_login'''
        return self.user.get_id()

    def data_profiling(self):
        '''Provides access to data profiling tools'''
        return True

    def is_superuser(self):
        '''Access all the things'''
        return True


class AuthenticationError(Exception):
    pass


class OIDCAuthBackend(object):

    def __init__(self):
        self.oidc_host = get_config_param('host')
        self.oidc_path = get_config_param('oidc_path')
        self.login_manager = flask_login.LoginManager()
        self.login_manager.login_view = 'airflow.login'
        self.flask_app = None
        self.oidc_oauth = None

    def oidc_api_route(self, leaf):
        api_url = self.oidc_host + '/' + self.oidc_path
        return 'https://' + api_url + leaf

    def init_app(self, flask_app):
        self.flask_app = flask_app

        self.login_manager.init_app(self.flask_app)

        self.oidc_oauth = OAuth(self.flask_app).remote_app(
            'oidc',
            consumer_key=get_config_param('client_id'),
            consumer_secret=get_config_param('client_secret'),
            request_token_params={'scope': 'openid'},
            base_url=self.oidc_host,
            request_token_url=None,
            access_token_method='POST',
            access_token_url=self.oidc_api_route('/token'),
            authorize_url=self.oidc_api_route('/auth')
        )

        self.login_manager.user_loader(self.load_user)

        self.flask_app.add_url_rule(get_config_param('oauth_callback_route'),
                                    'oidc_oauth_callback',
                                    self.oauth_callback)

    def login(self, request):
        log.debug('Redirecting user to OIDC login')
        return self.oidc_oauth.authorize(callback=url_for(
            'oidc_oauth_callback',
            _external=True,
            next=request.args.get('next') or request.referrer or None))

    def get_oidc_user_profile_info(self, oidc_token):
        resp = self.oidc_oauth.get(self.oidc_api_route('/userinfo'), 
                                   token=(oidc_token,''))

        if not resp or resp.status != 200:
            raise AuthenticationError(
                'Failed to fetch user profile, status ({0})'.format(
                    resp.status if resp else 'None'))

        return resp.data['preferred_username'], resp.data['email']

    @provide_session
    def load_user(self, userid, session=None):
        if not userid or userid == 'None':
            return None

        user = session.query(models.User).filter(
            models.User.id == int(userid)).first()
        return OIDCUser(user)

    @provide_session
    def oauth_callback(self, session=None):
        log.debug('OIDC OAuth callback called')

        next_url = request.args.get('next') or url_for('admin.index')
        
        resp = self.oidc_oauth.authorized_response()
        
        try:
            if resp is None:
                raise AuthenticationError(
                    'Null response from OIDC, denying access.'
                )

            oidc_token = resp['access_token']

            username, email = self.get_oidc_user_profile_info(oidc_token)

        except AuthenticationError:
            log.exception('')
            return redirect(url_for('airflow.noaccess'))

        user = session.query(models.User).filter(
            models.User.username == username).first()

        if not user:
            user = models.User(
                username=username,
                email=email,
                is_superuser=False)

        session.merge(user)
        session.commit()
        login_user(OIDCUser(user))
        session.commit()

        return redirect(next_url)

login_manager = OIDCAuthBackend()


def login(self, request):
    return login_manager.login(request)
