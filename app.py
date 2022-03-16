import re

from datetime import datetime
from slugify import slugify

from flask import Flask, flash, render_template, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_login import (
    UserMixin, LoginManager, current_user,
    login_user, logout_user, login_required)
from urllib.parse import urljoin
from werkzeug import secure_filename
from werkzeug.contrib.atom import AtomFeed
from flask_wtf.file import FileField, FileAllowed
from wtforms.fields import (
    StringField, TextAreaField, SubmitField, SelectField,
    PasswordField, BooleanField, HiddenField)
from wtforms.fields.html5 import EmailField
from wtforms.validators import (
    DataRequired, Email, EqualTo, Length, ValidationError, URL, Optional)

app = Flask(__name__)

app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///flaskblog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

login_manager = LoginManager(app)
login_manager.login_view = 'login'
db = SQLAlchemy(app)

# MODELS


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


entry_tags = db.Table('entry_tags',
                      db.Column('tag_id', db.Integer, db.ForeignKey('tag.id')),
                      db.Column('entry_id', db.Integer,
                                db.ForeignKey('entry.id'))
                      )


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    joined = db.Column(db.DateTime, default=datetime.now)
    entries = db.relationship('Entry', backref='author', lazy='dynamic')

    # Password setup

    def __repr__(self):
        return f'{self.username}'


class Entry(db.Model):
    PUBLISHED = 0
    DRAFT = 1
    DELETED = 2

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True)
    body = db.Column(db.Text, nullable=False)
    created = db.Column(db.DateTime, default=datetime.now, nullable=False)
    updated = db.Column(db.DateTime, default=datetime.now,
                        onupdate=datetime.now)
    status = db.Column(db.SmallInteger, default=PUBLISHED)
    # Queries the Tag model via the entry_tags assoc table; then create
    # a backref on the Tag model with entries & returns a Queryset object
    tags = db.relationship('Tag', secondary=entry_tags,
                           backref=db.backref('entries', lazy='dynamic'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='entry', lazy='dynamic')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.generate_slug()

    def __repr__(self):
        return f'Entry: {self.title}'

    def get_absolute_url(self):
        return url_for('entry', slug=self.slug)

    def generate_slug(self):
        slug = self.slug
        if not slug:
            slug = slugify(self.title)


class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    slug = db.Column(db.String(64), unique=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.slug = slugify(self.name)

    def __repr__(self):
        return f'Tag: {self.name}'


class Comment(db.Model):

    STATUS_PENDING_MODERATION = 0
    STATUS_PUBLIC = 1
    STATUS_SPAM = 8
    STATUS_DELETED = 9

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    email = db.Column(db.String(64))
    url = db.Column(db.String(100))
    ip_address = db.Column(db.String(64))
    body = db.Column(db.Text)
    status = db.Column(db.SmallInteger, default=STATUS_PUBLIC)
    created = db.Column(
        db.DateTime(timezone=True),
        default=datetime.now)
    entry_id = db.Column(db.Integer, db.ForeignKey('entry.id'))

    def __repr__(self):
        return f'<Comment from {self.name}>'


# FORMS

def is_proper_username(form, field):
    if not re.match(r"^\w+$", field.data):
        msg = f"{field.name} should not have any of these characters \
                only: a-z0-9_"
        raise ValidationError(msg)


class TagField(StringField):
    def _value(self):
        if self.data:
            # Display tags as a comma-separated list.
            return ', '.join([tag.name for tag in self.data])
        return ''

    def get_tags_from_string(self, tag_string):
        raw_tags = tag_string.split(',')

        # Filter out any empty tag names.
        tag_names = [name.strip() for name in raw_tags if name.strip()]

        # Query the database and retrieve any tags we have already saved.
        existing_tags = Tag.query.filter(Tag.name.in_(tag_names))

        # Determine which tag names are new.
        new_names = set(tag_names) - set([tag.name for tag in existing_tags])

        # Create a list of unsaved Tag instances for the new tags.
        new_tags = [Tag(name=name) for name in new_names]

        # Return all the existing tags and all the new, unsaved tags.
        return list(existing_tags) + new_tags

    def process_formdata(self, valuelist):
        if valuelist:
            self.data = self.get_tags_from_string(valuelist[0])
        else:
            self.data = []


class LoginForm(FlaskForm):
    email = EmailField('Email',
                       validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me?')
    submit = SubmitField('Login')


class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), is_proper_username,
                                       Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(),
                                                 EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError(
                'That username is taken. Please choose a different one.')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError(
                'That email is taken. Please choose a different one.')

    @staticmethod
    def validate_password(form, field):
        data = field.data
        if not re.findall('.*[a-z].*', data):
            msg = f"{field.name} should have at least one lowercase character."
            raise ValidationError(msg)
        if not re.findall('.*[A-Z].*', data):
            msg = f"{field.name} should have at least one uppercase character"
            raise ValidationError(msg)
        if not re.findall('.*[0-9].*', data):
            msg = f"{field.name} should have at least one number"
            raise ValidationError(msg)
        if not re.findall(r".*[^ a-zA-Z0-9].*", data):
            msg = f"{field.name} should have at least one special character"
            raise ValidationError(msg)


class UpdateAccountForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = EmailField('Email',
                       validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture', validators=[
                        FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError(
                    'That username is taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError(
                    'That email is taken. Please choose a different one.')


class EntryForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    image = FileField('Image', validators=[FileAllowed(['jpg', 'png'])])
    body = TextAreaField('Body', validators=[DataRequired()])
    status = SelectField('Status', choices=(
        (Entry.PUBLISHED, 'Published'),
        (Entry.DRAFT, 'Draft')), coerce=int)
    tags = TagField(
        'Tags',
        description='Separate multiple tags with commas.')
    submit = SubmitField('Publish')

    def save_entry(self, entry):
        self.populate_obj(entry)
        entry.generate_slug()
        return entry


class CommentForm(FlaskForm):
    name = StringField('Name',
                       validators=[DataRequired()])
    email = EmailField('Email',
                       validators=[DataRequired(), Email()])
    url = StringField('URL',
                      validators=[Optional(), URL()])
    body = TextAreaField('Comment',
                         validators=[DataRequired(), Length(min=10, max=3000)])
    entry_id = HiddenField(validators=[DataRequired()])

    def validate(self):
        if not super().validate():
            return False

        # Ensure that entry_id maps to a public Entry.
        entry = Entry.query.filter(
            (Entry.status == Entry.STATUS_PUBLIC) &
            (Entry.id == self.entry_id.data)).first()

        if not entry:
            return False
        return True


# HELPERS

def object_list(template_name, query, paginate_by=5, **context):
    page = request.args.get('page')
    if page and page.isdigit():
        page = int(page)
    else:
        page = 1
    object_list = query.paginate(page, paginate_by)
    return render_template(template_name, object_list=object_list, **context)


def entry_list(template_name, query, **context):
    """ Filter results based on search query"""
    query = filter_status_by_user(query)
    valid_statuses = (Entry.DRAFT, Entry.PUBLISHED)
    query = query.filter(Entry.status.in_(valid_statuses))
    if request.args.get('q'):
        search = request.args['q']
        query = query.filter(
            (Entry.body.contains(search)) | (Entry.title.contains(search)))
    return object_list(template_name, query, **context)


def get_entry_or_404(slug, author=None):
    """
    Helper function used to extract entries from the database by the
    given slug.
    """
    query = Entry.query.filter(Entry.slug == slug)
    if author:
        query = query.filter(Entry.author == author)
    else:
        query = filter_status_by_user(query)
    return query.first_or_404()


def filter_status_by_user(query):
    """
    Helper function filter shown entries by the user status.
    Only published entries accessible for non authenticated users.
    """
    if not current_user.is_authenticated:
        query = query.filter(Entry.status == Entry.PUBLISHED)
    else:
        # Allow users to view their own drafts
        query = query.filter(
            (Entry.status == Entry.PUBLISHED) |
            ((Entry.author == current_user) &
                (Entry.status != Entry.DELETED)))
    return query


# VIEWS

# Track the last page a user visited
# @app.before_request
# def _last_page_visited():
#      if "current_page" in session:
#      session["last_page"] = session["current_page"]
#      session["current_page"] = request.path


@app.route('/')
def home():
    page = request.args.get('page', 1, type=int)
    entries = Entry.query.order_by(Entry.created.desc()) \
                         .paginate(page=page, per_page=5)
    return entry_list('home.html', entries)


@app.route('/tags/')
def tags():
    # List tags with only one or more queries
    # Tag.query.join(entry_tags).distinct()
    # Display the number of entries in each tag
    tags = Tag.query.order_by(Tag.name)
    return object_list('tags.html', tags)


@app.route('/tag/<slug>/')
def tag(slug):
    tag = Tag.query.filter(Tag.slug == slug).first_or_404()
    entries = tag.entries.order_by(Entry.created.desc())
    return object_list('tag.html', entries, tag=tag)


@login_required
@app.route('/create/', methods=['GET', 'POST'])
def create():
    if request.method == 'POST':
        form = EntryForm(request.form)
        if form.validate():
            # image_file = request.files['file']
            # filename = secure_filename(image_file.filename)
            # image_file.save(filename)
            entry = form.save_entry(Entry(
                author=current_user._get_current_object()))
            db.session.add(entry)
            db.session.commit()
            flash(f'Entry {entry.title} created successfully', 'success')
            return redirect(url_for('post', slug=entry.slug))
    else:
        form = EntryForm()
    return render_template('form.html', form=form)


@app.route('/<slug>/')
def post(slug):
    entry = get_entry_or_404(slug)
    form = CommentForm(data={'entry_id': entry.id})
    return render_template('post.html', entry=entry, form=form)


@login_required
@app.route('/<slug>/edit/', methods=['GET', 'POST'])
def edit(slug):
    entry = get_entry_or_404(slug, author=None)
    if request.method == 'POST':
        form = EntryForm(request.form, obj=entry)
        if form.validate():
            entry = form.save_entry(entry)
            db.session.add(entry)
            db.session.commit()
            return redirect(url_for('post', slug=entry.slug))
    else:
        form = EntryForm(obj=entry)
    return render_template('edit.html', entry=entry, form=form)


@login_required
@app.route('/<slug>/delete/', methods=['GET', 'POST'])
def delete(slug):
    # entry = get_entry_or_404(slug, author=None)
    entry = Entry.query.filter(Entry.slug == slug).first_or_404()
    if request.method == 'POST':
        entry.status = Entry.DELETED
        db.session.add(entry)
        db.session.commit()
        flash(f'Entry {entry.title} has been deleted successfully', 'success')
        return redirect(url_for('home'))
    return render_template('delete.html', entry=entry)


@app.route('/login/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, remember=form.remember.data)
            next = request.args.get('next')
            return redirect(next) if next else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please try again', 'danger')
    return render_template('login.html', form=form)


@login_required
@app.route('/logout/')
def logout():
    logout_user()
    return redirect(request.args.get('next') or url_for('home'))


@app.route('/feeds/')
def recent_feed():
    """
    View used to create Atom feeds to the blog readers
    """
    feed = AtomFeed(
        'Latest Blog Posts',
        feed_url=request.url,
        url=request.url_root,
        author=request.url_root
    )
    entries = Entry.query.filter(Entry.status == Entry.PUBLISHED).\
        order_by(Entry.created.desc()).limit(15).all()

    for entry in entries:
        feed.add(
            entry.title,
            entry.body,
            content_type='html',
            url=urljoin(request.url_root, url_for(
                'post', slug=entry.slug)),
            updated=entry.updated,
            published=entry.created)

    return feed.get_response()
