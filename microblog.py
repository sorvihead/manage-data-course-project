from app import create_app, db, cli
from app.models import Comment, Tag, Like, Role, Permission
from app.models import User, Post, Message, Notification, Task

app = create_app()
app.jinja_env.globals.update(Permission=Permission)
cli.register(app)


@app.shell_context_processor
def make_shell_contexts():
    return {'db': db, 'User': User, 'Post': Post, 'Message': Message,
            'Notification': Notification, 'Task': Task, 'Comment': Comment,
            'Permission': Permission, 'Role': Role, 'Like': Like, 'Tag': Tag}

