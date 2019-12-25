import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))


class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    LOG_TO_STDOUT = os.environ.get('LOG_TO_STDOUT')
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 25)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS') is not None
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    ADMINS = ['novoid86@yandex.ru', 'shaman0211@gmail.com']
    LANGUAGES = ['en', 'es']
    ES_HOST = os.environ.get('ES_HOST') or 'elasticsearch'
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://'
    POSTS_PER_PAGE = 25
    COMMENTS_PER_PAGE = 10
    INFLUXDB_HOST = os.environ.get('INFLUXDB_HOST') or 'influxdb'
    INFLUXDB_DATABASE = os.environ.get('INFLUXDB_DATABASE') or 'telegraf'
    INFLUXDB_TIMEOUT = 10
