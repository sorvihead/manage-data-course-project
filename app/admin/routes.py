from app.admin import bp
from datetime import datetime

from flask import render_template, flash, redirect, url_for, request, g, \
    jsonify, current_app, abort, make_response
from flask_babel import _, get_locale
from flask_login import current_user, login_required

from app import db
from app.decorators import admin_required, permission_required
from app.models import User, Post, Message, Notification, Permission, Role, Comment, Like, Task, Tag
from app.translate import translate


@bp.route('/')
@login_required
@admin_required
def admin():
    tables = ['User', 'Message', 'Notification', 'Permission', 'Role', 'Comment', 'Like', 'Task', 'Comment', 'Tag']
    return render_template('admin/admin.html', tables=tables)


@bp.route('/<string:table>')
@login_required
@admin_required
def tables(table):
    if User.__tablename__.lower() == table.lower():
        query = User.query
    if Post.__tablename__.lower() == table.lower():
        query = Post.query
    if Role.__tablename__.lower() == table.lower():
        query = Role.query
    if Message.__tablename__.lower() == table.lower():
        query = Message.query
    if Notification.__tablename__.lower() == table.lower():
        query = Notification.query
    if Task.__tablename__.lower() == table.lower():
        query = Task.query
    if Comment.__tablename__.lower() == table.lower():
        query = Comment.query
    if Like.__tablename__.lower() == table.lower():
        query = Like.query
    if Tag.__tablename__.lower() == table.lower():
        query = Tag.query
