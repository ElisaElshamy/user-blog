import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'L2ssveKnomWHRcL4'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def error_message(error_code):
    error_code = str(error_code)

    if error_code == '1':
        error_msg = "You must be logged in to create posts"

    elif error_code == '2':
        error_msg = "You must be logged in to view the dashboard"

    elif error_code == '3':
        error_msg = "You must be logged in to view posts"

    elif error_code == '4':
        error_msg = "Subject and content are required fields"

    elif error_code == '5':
        error_msg = "You must be logged in to edit posts"

    elif error_code == '6':
        error_msg = ("Permission denied. You must be logged "
                     "in as the author of that post")

    elif error_code == '7':
        error_msg = "You must be logged in to delete posts"

    elif error_code == '8':
        error_msg = "Nice try! But you cannot Like your own posts!"

    elif error_code == '9':
        error_msg = "You must be logged in to Like posts"

    elif error_code == '10':
        error_msg = "You are not logged in"

    else:
        error_msg = ""

    return error_msg


class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

# USER STUFF


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# BLOG FUNCTIONALITY
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

# BLOG POST DATA MODEL


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.StringProperty(required=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

# BLOG HOME PAGE


class BlogFront(BlogHandler):

    def get(self):
        if not self.user:
            username = ''
        else:
            username = self.user.name

        posts = Post.all().order('-created')
        user_liked = Likedby.all()
        user_comments = Comment.all()
        comments_liked = CommentLiked.all()

        error_msg = error_message(self.request.get('error'))

        self.render('front.html', posts=posts, username=username,
                    likes=user_liked, comments=user_comments,
                    commentlikes=comments_liked, error=error_msg)

    def post(self):
        self.request.get('submit')

# DISPLAY SINGLE POST


class PostPage(BlogHandler):

    def get(self, post_id):
        if not self.user:
            username = ''
        else:
            username = self.user.name

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return
        self.render("permalink.html", post=post, username=username)

# CREATE POSTS


class NewPost(BlogHandler):

    def get(self):
        if self.user:
            self.render("newpost.html", username=self.user.name)
        else:
            # User is not logged in
            self.redirect("/login?error=1")

    def post(self):
        if not self.user:
            self.redirect('/login?error=10')

        else:
            author = self.user.name
            subject = self.request.get('subject')
            content = self.request.get('content')

            if self.request.get('submit') == "Save Entry":
                if subject and content:
                    p = Post(parent=blog_key(), subject=subject,
                             content=content, author=author)
                    p.put()

                    self.redirect('/blog/%s' % str(p.key().id()))

                else:
                    error_msg = error_message(4)
                    self.render("newpost.html", subject=subject,
                                content=content,
                                username=self.user.name, error=error_msg)
            else:
                # If cancelled
                self.redirect('/blog')

# SHOW ONLY USER'S POSTS


class UserPosts(BlogHandler):

    def get(self):
        if self.user:
            username = str(self.user.name)
            posts = Post.all().filter('author =', username)

            self.render("user_posts.html", posts=posts, username=username)
        else:
            self.redirect("/login?error=3")

# EDIT OWN POST


class Edit(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user:
            if post.author == self.user.name:

                subject = post.subject
                content = post.content

                self.render("edit.html", subject=subject,
                            content=content, username=self.user.name, error="")
            else:
                self.redirect("/blog?error=6")
        else:
            self.redirect("/login?error=5")

    def post(self, post_id):
        if self.request.get('submit') == "Save Entry":

            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if self.user:
                if post.author == self.user.name:
                    post.subject = self.request.get('subject')
                    post.content = self.request.get('content')
                    post.put()
                    self.redirect("/blog")
                else:
                    self.redirect("/blog?error=6")
            else:
                self.redirect("/login?error=5")
        else:
            # If cancelled
            self.redirect("/blog")

# DELETE OWN POST


class Delete(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        subject = post.subject

        if self.user:
            if self.user.name == post.author:
                self.render("delete.html", subject=subject,
                            username=self.user.name)

            else:
                self.redirect("/blog?error=6")

        else:
            self.redirect("/login?error=7")

    def post(self, post_id):
        if self.request.get('submit') == "Delete":
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if self.user:
                if self.user.name == post.author:
                    # We MUST delete every associated with that post
                    for comment in post.comments:

                        for commentlike in comment.comment_liked:
                            commentlike.delete()

                        comment.delete()

                    for like in post.liked_by:
                        like.delete()

                    db.delete(post)
                    self.redirect("/blog")
                else:
                    self.redirect("/blog?error=6")

            else:
                self.redirect("/login?error=7")

        else:
            # If cancelled
            self.redirect("/blog")

# LIKE POST DATA MODEL


class Likedby(db.Model):
    # One to many relationship.  References blog post
    post = db.ReferenceProperty(Post, collection_name='liked_by')
    username = db.StringProperty(required=True)

# LIKE BLOG POST


class Like(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user and self.user.name == post.author:
            self.redirect("/blog?error=8")

        elif self.user and self.user.name != post.author:
            Likedby(post=post, username=str(self.user.name)).put()
            self.redirect("/blog")

        else:
            self.redirect("/login?error=9")

# UNLIKE PREVIOUS


class Unlike(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not self.user:
            self.redirect("/login?error=10")

        else:
            username = self.user.name
            post.liked_by.filter('username =', str(
                self.user.name)).get().delete()

            self.redirect("/blog")

# COMMENT DATA MODEL


class Comment(db.Model):
    # One to many relationship.  References blog post
    post = db.ReferenceProperty(Post, collection_name='comments')
    author = db.StringProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", c=self)


class CommentPage(BlogHandler):

    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        if not comment:
            self.error(404)
            return

        self.render("commentpermalink.html", comment=comment)

# SHOW ONLY USER'S COMMENTS


class UserComments(BlogHandler):

    def get(self):
        if self.user:
            username = str(self.user.name)
            comments = Comment.all().filter('author =', username)

            self.render("user_comments.html",
                        comments=comments, username=username)
        else:
            self.redirect("/login?error=3")

# ADD A COMMENT


class AddComment(BlogHandler):

    def get(self, post_id):
        if self.user:
            self.render("addcomment.html", username=self.user.name)
        else:
            self.redirect("/login?error=10")

    def post(self, post_id):
        if not self.user:
            self.redirect("/login?error=10")
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            author = self.user.name
            subject = self.request.get('subject')
            content = self.request.get('content')

            if self.request.get('submit') == "Save Entry":
                if subject and content:

                    Comment(post=post, author=author,
                            subject=subject, content=content).put()
                    self.redirect('/blog')

                else:
                    error_msg = error_message(4)
                    self.render("addcomment.html", subject=subject,
                                content=content,
                                username=self.user.name, error=error_msg)
            else:
                # If cancelled
                self.redirect('/blog')

# EDIT OWN COMMENT


class EditComment(BlogHandler):

    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        if self.user:
            if comment.author == self.user.name:

                subject = comment.subject
                content = comment.content

                self.render("editcomment.html", subject=subject,
                            content=content, username=self.user.name, error="")
            else:
                self.redirect("/blog?error=6")
        else:
            self.redirect("/login?error=5")

    def post(self, comment_id):
        if self.request.get('submit') == "Save Entry":

            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)

            if self.user:
                if comment.author == self.user.name:
                    comment.subject = self.request.get('subject')
                    comment.content = self.request.get('content')
                    comment.put()
                    self.redirect("/blog")

                else:
                    self.redirect("/blog?error=6")
            else:
                self.redirect("/login?error=5")
        else:
            # If cancelled
            self.redirect("/blog")

# DELETE OWN COMMENT


class DeleteComment(BlogHandler):

    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        subject = comment.subject

        if self.user:
            if self.user.name == comment.author:
                self.render("deletecomment.html", subject=subject,
                            username=self.user.name)

            else:
                self.redirect("/blog?error=6")

        else:
            self.redirect("/login?error=5")

    def post(self, comment_id):
        if self.request.get('submit') == "Delete":
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)

            if self.user:
                if self.user.name == comment.author:
                    # We MUST delete everything associated with that comment
                    for commentlike in comment.comment_liked:
                        commentlike.delete()

                    db.delete(comment)
                    self.redirect("/blog")
                else:
                    self.redirect("/blog?error=6")

            else:
                self.redirect("/login?error=5")
        else:
            # If delete was successful or cancelled
            self.redirect("/blog")

# LIKED COMMENT DATA MODEL


class CommentLiked(db.Model):
    # One to many relationship.  References blog post
    comment = db.ReferenceProperty(Comment, collection_name='comment_liked')
    username = db.StringProperty(required=True)

# LIKED COMMENTS


class LikeComment(BlogHandler):

    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        if self.user and self.user.name == comment.author:
            self.redirect("/blog?error=8")

        elif self.user and self.user.name != comment.author:
            CommentLiked(comment=comment, username=str(self.user.name)).put()
            self.redirect("/blog")

        else:
            self.redirect("/login?error=9")

# UNLIKE COMMENTS


class UnlikeComment(BlogHandler):

    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        if not self.user:
            self.redirect("/login?error=10")

        else:
            username = self.user.name
            comment.comment_liked.filter(
                'username =', str(self.user.name)).get().delete()

            self.redirect("/blog")


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):

    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


class Login(BlogHandler):

    def get(self):

        error_msg = error_message(self.request.get('error'))
        self.render('login-form.html', error=error_msg)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect('/blog')


class Welcome(BlogHandler):

    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/login?error=2')


app = webapp2.WSGIApplication([('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ('/blog/posts', UserPosts),
                               ('/blog/edit/([0-9]+)', Edit),
                               ('/blog/delete/([0-9]+)', Delete),
                               ('/blog/like/([0-9]+)', Like),
                               ('/blog/unlike/([0-9]+)', Unlike),
                               ('/blog/comment/([0-9]+)', CommentPage),
                               ('/blog/comments', UserComments),
                               ('/blog/addcomment/([0-9]+)', AddComment),
                               ('/blog/editcomment/([0-9]+)', EditComment),
                               ('/blog/deletecomment/([0-9]+)', DeleteComment),
                               ('/blog/comment/like/([0-9]+)', LikeComment),
                               ('/blog/comment/unlike/([0-9]+)',
                                UnlikeComment),
                               ],
                              debug=True)
