import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import ndb

# initialize Jinja2
# adds 'templates' to the end of the current file directory to list where the template directory is
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
# tell jinja where to render templates from
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)
# sets string for hmac
secret = 'python'


# global render function for Jinja templates
# takes a file name and extra parameters
def render_str(template, **params):
    # call get template on the jinja env and give it a file name and store it in the variable t
    t = jinja_env.get_template(template)
    # this will return a string
    return t.render(params)


# create a secure value using hmac and secret
def make_secure_val(val):
    # returns value | hmac
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


# makes sure secure val is equal to the val in make_secure_val
def check_secure_val(secure_val):
    # find the hmac value
    val = secure_val.split('|')[0]
    # compare the secure values
    if secure_val == make_secure_val(val):
        return val


# create BlogHandler class that uses webapp2 framework
class BlogHandler(webapp2.RequestHandler):
    """Main Blog Handler inherited by other Handlers"""

    # An instance of the Response class represents the data to be sent in response to a web request
    # The response object's out property is a file-like object that can be used for writing the body of the response.
    # https://cloud.google.com/appengine/docs/standard/python/tools/webapp/responseclass#constructor_1
    
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    # class level render function with self, and user param
    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    # class level render function render_str + write
    # sends render_str back to the browser
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # sets cookie to a secure hashed value
    def set_secure_cookie(self, name, val):
        # set cookie_val to make_secure_val
        cookie_val = make_secure_val(val)
        # an instance of the Response class represents the data to be sent in response to a web request
        # set the cookie with it's name and value
        self.response.headers.add_header(
            'Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    # gets cookie and checks match for the value
    def read_secure_cookie(self, name):
        # get the cookie_val
        cookie_val = self.request.cookies.get(name)
        # 
        return cookie_val and check_secure_val(cookie_val)

    # uses cookie to keep user logged in
    def login(self, user):
        # set find the users id and set it to 'user_id'
        self.set_secure_cookie('user_id', str(user.key.id()))

    # uses cookie to log user out
    def logout(self):
        # set the users cookie id to nothing
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # checks cookie on every page to keep user logged in
    # every request calls initialize
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        # reads the secure cookie user_id
        uid = self.read_secure_cookie('user_id')
        # if valid, sets self.user to that value
        self.user = uid and User.by_id(int(uid))


# render specific to a post
def render_post(response, post):
    # render the post subject with line breaks
    response.out.write('<b>' + post.subject + '</b><br>')
    # render the post content
    response.out.write(post.content)


# class for example write
class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, Udacity! Here is my blog')
        self.redirect('/blog')


# user stuff
# creates password salts, hashes pass, validates hashes' pass
def make_salt(length=5):
    # returns a string of 5 random letters
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    # make new salt if it does not exist
    if not salt:
        salt = make_salt()
    # create the hash and store it in a variable
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

# pass in the hashed password
def valid_pw(name, password, h):
    # find the salt stored in the variable h
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


# creates user group for multiple blogs
def users_key(group='default'):
    return ndb.Key('users', group)


# model stores user info in db
class User(ndb.Model):
    name = ndb.StringProperty(required=True)
    pw_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty()

    # get user by id shortcut
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    # get user by name shortcut
    @classmethod
    def by_name(cls, name):
        u = User.query().filter(ndb.GenericProperty('name') == name).get()
        return u

    # check/validate user pass on signup
    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    # checks user and pass for login
    @classmethod
    def login(cls, name, pw):
        # calls the by_name function
        # use cls instead of User so we can overwrite it later
        u = cls.by_name(name)
        # if it exists and has a valid password
        if u and valid_pw(name, pw, u.pw_hash):
            # return the user
            return u


# blog stuff
# creates parent/ancestor for strong consistancy
def blog_key(name='default'):
    return ndb.Key('blogs', name)


# creates parent/ancestor for strong consistancy
def com_key(name='default'):
    return ndb.Key('comments', name)


# Post model to store Post info in the database
class Post(ndb.Model, BlogHandler):
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    author = ndb.IntegerProperty(required=True)
    name = ndb.StringProperty(required=True)
    like_count = ndb.IntegerProperty(default=0)

    # renders post content with <br> instead of \n
    def render(self, user):
        self._render_text = self.content.replace('\n', '<br>')
        # render template, post and user
        return render_str("post.html", p=self, user=user)


# like model stores like info
class Like(ndb.Model, BlogHandler):
    # user is required to like
    # Cloud Datastore key Optional keyword argument: kind=kind, to require  # that keys assigned to this property always have the indicated kind. 
    # May be a string or a Model subclass.
    user = ndb.KeyProperty(kind='User', required=True)


# Comment model to store comment info
class Comment(ndb.Model, BlogHandler):
    comment = ndb.StringProperty(required=True)
    post = ndb.KeyProperty(kind='Post', required=True)
    user = ndb.KeyProperty(kind='User', required=True)
    name = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)


# retrieves comments for post and updates with each new comment
class CommentPage(BlogHandler):
    def get(self, post_id):
        # set the key for the post
        post_key = ndb.Key('Post', int(post_id), parent=blog_key())
        # send a get request to set post to post_key value
        post = post_key.get()
        
        # set comments to return the comments in order of newest first
        comments = Comment.query(ancestor=com_key()).filter(
                                 Comment.post == post_key).order(
                                 -Comment.created)
       
        if not self.user:
            self.redirect('/signup')
        if not post:
            self.error(404)
            return

        self.render("comments.html",
                    post=post,
                    comments=comments)
        
    # define comment post
    def post(self, post_id):
        # link to the post id and blog key
        post_key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = post_key.get()
        
        # error handling
        if not self.user:
            return self.redirect('/login')
        if not post:
            self.error(404)
            return
        
        # define comment model parameters
        comment = self.request.get('comment')
        user = self.user
        name = self.user.name
        comments = Comment.query(ancestor=com_key()).filter(
                                 Comment.post == post_key).order(
                                 -Comment.created)
        # post the comment
        if comment:
            c = Comment(parent=com_key(),
                        comment=comment,
                        post=post.key,
                        user=user.key,
                        name=name)
            c.put()
            self.redirect('/blog/comments/%s' % post_id)
            
        # error handling for blank comment
        else:
            error = "no blank comments"
            self.render("comments.html",
                        error=error,
                        post=post,
                        comments=comments)

class CommentEdit(BlogHandler):
    """allows auth user to edit comment"""
    def get(self, com_id):
        # find the comment key
        key = ndb.Key('Comment', int(com_id), parent=com_key())
        Comment = key.get()
        
        # error handling
        if not Comment:
            return self.error(404)

        if self.user and self.user.key == Comment.user:
            comment_txt = Comment.comment
            self.render("edit-com.html",
                        comment=comment_txt)
        else:
            self.redirect('/blog')

    def post(self, com_id):
        key = ndb.Key('Comment', int(com_id), parent=com_key())
        Comment = key.get()

        if not Comment:
            return self.error(404)

        if self.user and self.user.key == Comment.user:
            cancel = self.request.get("cancel")
            if cancel:
                self.redirect('/blog/comments/%s' % Comment.post.id())
                print "POST ID", Comment.post.id()
            else:
                # updates post Model with edited subject/content
                comment_txt = self.request.get('comment')
                if comment_txt:
                    Comment.comment = comment_txt
                    Comment.put()
                    self.redirect('/blog/comments/%s' % Comment.post.id())
                else:
                    error = "comment requires text, please!"
                    self.render("edit-com.html",
                                comment=Comment.comment,
                                error=error)
        else:
            return self.redirect('/login')


class CommentDelete(BlogHandler):
    """allows auth user to delete comment"""
    def get(self, com_id):
        key = ndb.Key('Comment', int(com_id), parent=com_key())
        Comment = key.get()

        if not Comment:
            return self.error(404)

        if self.user and self.user.key == Comment.user:
            comment_txt = Comment.comment
            self.render("delete-com.html",
                        comment=comment_txt,
                        name=Comment.name)
        else:
            self.redirect('/blog')

    def post(self, com_id):
        key = ndb.Key('Comment', int(com_id), parent=com_key())
        Comment = key.get()

        if not Comment:
            return self.error(404)

        post_key = ndb.Key('Post', int(Comment.post.id()), parent=blog_key())
        post = key.get()

        if self.user and self.user.key == Comment.user:
            yes_delete = self.request.get('delete')
            # checks to make sure user wants to delete post
            if yes_delete:
                ndb.Key('Comment', int(com_id), parent=com_key()).delete()
                self.redirect('/blog')
            else:
                self.redirect('/blog/comments/%s' % post.key.id())
        else:
            self.redirect('/login')


# Renders Posts for main page by newest post
class BlogFront(BlogHandler):
    def get(self):
        posts = Post.query(ancestor=blog_key()).order(-Post.created)
        self.render('front.html', posts=posts)

    # handles likes for front page
    def post(self):
        post_id = self.request.get("like")

        post_key = ndb.Key('Post', int(post_id), parent=blog_key())

        a_post = post_key.get()

        cur_user = self.user

        # checks if user has liked it already
        likes = Like.query(ancestor=post_key).filter(cur_user.key ==
                                                     Like.user).fetch()

        # increments the likes for the post on click
        if post_key:
            if cur_user:
                if cur_user.key.id() != a_post.author:
                    if likes == []:
                        a_post.like_count = a_post.like_count + 1
                        a_post.put()
                        print "#LIKE COUNT", a_post.like_count
                        print "#LIKES", likes
                        l = Like(parent=post_key,
                                 user=cur_user.key)
                        l.put()
                        self.redirect('/blog')

                    else:
                        likes[0].key.delete()
                        a_post.like_count = a_post.like_count - 1
                        a_post.put()
                        print "LIKE COUNT", a_post.like_count
                        self.redirect('/blog')
                        
    

# Post handler, after new post,
# redirect to permalink of post content
class PostPage(BlogHandler):
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


# Handler to create a new post
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.key.id()
        name = self.user.name

        if subject and content:
            p = Post(parent=blog_key(),
                     subject=subject,
                     content=content,
                     author=author,
                     name=name)
            p.put()
            self.redirect('/blog/%s' % str(p.key.id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html",
                        subject=subject,
                        content=content,
                        error=error)


# Handler to Edit Post
class EditPost(BlogHandler):
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()

        if not post:
            return self.error(404)

        if self.user and self.user.key.id() == post.author:
            subject = post.subject
            content = post.content
            self.render("editpost.html",
                        post=post,
                        subject=subject,
                        content=content)
        else:
            self.redirect('/blog')

    def post(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()

        if not post:
            return self.error(404)

        if self.user and self.user.key.id() == post.author:
            cancel = self.request.get("cancel")
            if cancel:
                self.redirect('/blog')
            else:
                # updates post Model with edited subject/content
                subject = self.request.get('subject')
                content = self.request.get('content')
                author = self.user.key.id()
                if subject and content:
                    post.subject = subject
                    post.content = content
                    post.author = author
                    post.put()
                    self.redirect('/blog')
                else:
                    error = "subject and content, please!"
                    self.render('/blog/editpost/%s' % p.key.id(),
                                subject=subject,
                                content=content,
                                error=error)
        else:
            return self.redirect('/login')


class DeletePost(BlogHandler):
    """allows auth user to delete post"""
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()

        if not post:
            return self.error(404)

        if self.user and self.user.key.id() == post.author:
            self.render("delete.html", post=post)
        else:
            self.redirect('/login')

    def post(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()

        if not post:
            return self.error(404)

        if self.user and self.user.key.id() == post.author:
            yes_delete = self.request.get('delete')
            # checks to make sure user wants to delete post
            if yes_delete:
                ndb.Key('Post', int(post_id), parent=blog_key()).delete()
                self.redirect('/blog')
            else:
                self.redirect('/blog')
        else:
            self.redirect('/login')


class Signup(BlogHandler):
    """Handler inherited by Register for user auth"""
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

        # errors for invalid inputs
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

    # sets flag for console, for succesful signup
    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    """Handler for user to register"""
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
    """Handler for registered user to login"""
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        # checks database and confirms values for valid user/pass
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    """logs user out"""
    def get(self):
        # calls self.logout
        self.logout()
        # redirects to the blog
        self.redirect('/blog')



app = webapp2.WSGIApplication([('/', MainPage),
                              ('/blog/?', BlogFront),
                              ('/blog/([0-9]+)', PostPage),
                              ('/blog/newpost', NewPost),
                              ('/blog/editpost/([0-9]+)', EditPost),
                              ('/blog/deletepost/([0-9]+)', DeletePost),
                              ('/blog/comments/([0-9]+)', CommentPage),
                              ('/blog/editcom/([0-9]+)', CommentEdit),
                              ('/blog/deletecom/([0-9]+)', CommentDelete),
                              ('/signup', Register),
                              ('/login', Login),
                              ('/logout', Logout),
                               ],
                              debug=True)
