from app import create_app, db, cli
from app.models import Comment
from app.models import User, Post, Message, Notification, Task

app = create_app()
cli.register(app)


@app.shell_context_processor
def make_shell_contexts():
    return {'db': db, 'User': User, 'Post': Post, 'Message': Message,
            'Notification': Notification, 'Task': Task, 'Comment': Comment}
